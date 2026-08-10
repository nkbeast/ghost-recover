// GHOST//RECOVER — carving engine.
//
// Two passes. The first sweeps the target with a single Aho-Corasick automaton
// across as many worker threads as the machine has cores and records candidate
// offsets. The second walks those candidates in disk order, validates each one
// against its format's structure, decides the real length, and streams the file
// out while hashing it.
//
// Behaviours the old single-pass carver got wrong and that matter here:
//   * files are no longer capped at 16 MB, so videos come out whole
//   * a candidate that lies inside an already-recovered file is skipped, which
//     removes the flood of embedded-thumbnail and false-positive results
//   * when a format cannot describe its own length, the file is bounded by the
//     next signature on disk instead of a blind 64 KB read
//   * dedup uses the whole file's hash, not a 4 KB prefix
#include "ghost/carve.h"

#include "ghost/util.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <thread>
#include <unordered_set>

namespace ghost {

namespace {

struct Candidate {
    i64 offset;     // where the file starts (signature offset minus magic_offset)
    int spec;
    int priority;
};

bool confirmMatches(DiskReader& disk, const CarveSpec& spec, i64 fileOffset, i64 avail) {
    if (spec.confirm.empty()) return true;
    if (spec.confirm_offset >= 0) {
        auto v = disk.readBlock((u64)(fileOffset + spec.confirm_offset), (i64)spec.confirm.size());
        return v.size() == spec.confirm.size() &&
               std::equal(v.begin(), v.end(), spec.confirm.begin());
    }
    i64 window = std::min<i64>(spec.confirm_window, avail);
    if (window <= 0) return false;
    auto v = disk.readBlock((u64)fileOffset, window);
    if (v.size() < spec.confirm.size()) return false;
    return std::search(v.begin(), v.end(), spec.confirm.begin(), spec.confirm.end()) != v.end();
}

// Scans forward for a footer, in overlapping windows so a footer straddling a
// read boundary is still found.
i64 findFooter(DiskReader& disk, i64 start, i64 limit, const std::vector<u8>& footer) {
    if (footer.empty()) return -1;
    const i64 kStep = 1 * 1024 * 1024;
    const i64 overlap = (i64)footer.size() - 1;
    i64 pos = 0;
    while (pos < limit) {
        i64 want = std::min(kStep, limit - pos);
        auto buf = disk.readBlock((u64)(start + pos), want);
        if (buf.size() < footer.size()) break;
        auto it = std::search(buf.begin(), buf.end(), footer.begin(), footer.end());
        if (it != buf.end()) return pos + (i64)(it - buf.begin()) + (i64)footer.size();
        if ((i64)buf.size() < want) break;
        if (want <= overlap) break;
        pos += want - overlap;
    }
    return -1;
}

// Trailing zero padding is slack, not file content. A heuristic-sized file
// (gzip, bzip2, ...) can end far from the next signature, so the run of zeros
// is walked back in overlapping windows instead of trusting the last 64 KiB.
i64 trimTrailingZeros(DiskReader& disk, i64 offset, i64 size) {
    if (size <= 0) return size;
    const i64 kStep = 4 * 1024 * 1024;
    i64 examined = 0;
    while (examined < size) {
        i64 look = std::min<i64>(kStep, size - examined);
        auto tail = disk.readBlock((u64)(offset + size - examined - look), look);
        if (tail.empty()) return size;
        i64 zeros = 0;
        for (i64 i = (i64)tail.size() - 1; i >= 0; i--) {
            if (tail[i] != 0) break;
            zeros++;
        }
        if (zeros < (i64)tail.size()) return size - examined - look + zeros;
        examined += look;
    }
    return 0;                                  // the whole candidate is zeros
}

std::string safeFormatName(const std::string& s) {
    std::string o;
    for (char c : s) o += (::isalnum((unsigned char)c) ? c : '_');
    return o;
}

}  // namespace

// ---------------------------------------------------------------------------

CarveResult carveDevice(DiskReader& disk, const CarveOptions& opt, Progress& prog) {
    CarveResult result;
    const i64 t0 = nowMs();
    result.image_size = disk.size();

    // ---- select the active signature set ---------------------------------
    const auto& registry = carverRegistry();
    std::vector<const CarveSpec*> specs;
    specs.reserve(registry.size());
    for (const auto& c : registry) {
        if (!opt.categories.empty() &&
            std::find(opt.categories.begin(), opt.categories.end(), c.category) == opt.categories.end())
            continue;
        if (!opt.extensions.empty() &&
            std::find(opt.extensions.begin(), opt.extensions.end(), c.ext) == opt.extensions.end())
            continue;
        specs.push_back(&c);
    }
    if (opt.write_files && writesBackOntoSource(opt.output_dir, disk.path())) {
        result.ok = false;
        result.error = "refusing to carve onto " + disk.path() +
                       ", the device being carved — that would overwrite the very data being "
                       "recovered. Choose a destination on a different disk.";
        return result;
    }
    result.signatures_loaded = (i64)specs.size();
    if (specs.empty()) {
        result.ok = false;
        result.error = "no carver signatures matched the requested categories/extensions";
        return result;
    }

    // ---- regions to sweep -------------------------------------------------
    std::vector<Extent> regions = opt.regions;
    if (regions.empty()) {
        i64 start = std::max<i64>(0, opt.start_offset);
        i64 end = opt.length > 0 ? std::min(result.image_size, start + opt.length) : result.image_size;
        if (end > start) regions.push_back(Extent(start, end - start));
    }
    i64 totalBytes = 0;
    for (const auto& r : regions) totalBytes += r.length;
    if (totalBytes <= 0) {
        result.ok = true;
        result.error = "nothing to scan (empty region set)";
        return result;
    }

    // ---- build the automaton ---------------------------------------------
    prog.setPhase("building signature automaton");
    MultiMatcher matcher;
    for (size_t i = 0; i < specs.size(); i++) matcher.add(specs[i]->magic, (int)i);
    matcher.build();

    // ---- pass 1: parallel signature sweep ---------------------------------
    prog.setPhase("scanning for signatures");
    prog.set(0, totalBytes);

    int threads = opt.threads > 0 ? opt.threads : (int)std::thread::hardware_concurrency();
    if (threads <= 0) threads = 2;
    threads = std::min(threads, 16);
    // Sequential reads beat parallelism on spinning media.
    if (disk.isRawDevice() && threads > 4) threads = 4;

    // Flatten the regions into fixed work units so threads stay balanced.
    struct Unit { i64 start, length; };
    std::vector<Unit> units;
    const i64 kUnit = 64 * 1024 * 1024;
    for (const auto& r : regions)
        for (i64 o = 0; o < r.length; o += kUnit)
            units.push_back({r.offset + o, std::min(kUnit, r.length - o)});
    if ((int)units.size() < threads) threads = std::max(1, (int)units.size());

    std::vector<Candidate> candidates;
    std::mutex candMutex;
    std::atomic<size_t> nextUnit{0};
    std::atomic<i64> scanned{0};
    std::atomic<bool> overflow{false};
    const size_t kMaxCandidates = 8 * 1000 * 1000;

    auto worker = [&]() {
        auto reader = disk.clone();
        if (!reader) return;
        std::vector<Candidate> local;
        local.reserve(4096);
        std::vector<u8> buf;
        const i64 kChunk = 4 * 1024 * 1024;
        const i64 overlap = (i64)matcher.maxPatternLen() - 1;

        while (!prog.cancelled()) {
            size_t idx = nextUnit.fetch_add(1);
            if (idx >= units.size()) break;
            Unit u = units[idx];
            // Start a little early so a signature straddling the unit boundary
            // is still seen; matches before the unit start are discarded.
            i64 readStart = std::max<i64>(0, u.start - overlap);
            i64 pos = readStart;
            i64 end = u.start + u.length;
            int state = matcher.initialState();

            while (pos < end && !prog.cancelled()) {
                i64 want = std::min(kChunk, end - pos);
                buf = reader->readBlock((u64)pos, want);
                if (buf.empty()) break;
                matcher.scan(buf.data(), buf.size(), pos, state,
                             [&](i64 hitOff, int specId) {
                                 // A signature that starts inside the overlap
                                 // window belongs to this unit: its final byte
                                 // lies at or beyond u.start, which the previous
                                 // unit never consumed. Anything starting before
                                 // the window is genuinely out of range.
                                 if (hitOff < readStart) return;
                                 const CarveSpec* sp = specs[(size_t)specId];
                                 i64 fileOff = hitOff - sp->magic_offset;
                                 if (fileOff < 0) return;
                                 local.push_back({fileOff, specId, sp->priority});
                             });
                pos += (i64)buf.size();
                scanned += (i64)buf.size();
                if ((scanned.load() & ((16 << 20) - 1)) == 0) prog.set(scanned.load(), totalBytes);
                if (local.size() > 200000) {
                    std::lock_guard<std::mutex> lk(candMutex);
                    if (candidates.size() + local.size() > kMaxCandidates) { overflow = true; }
                    else candidates.insert(candidates.end(), local.begin(), local.end());
                    local.clear();
                }
                if (overflow.load()) break;
            }
        }
        std::lock_guard<std::mutex> lk(candMutex);
        if (candidates.size() + local.size() <= kMaxCandidates)
            candidates.insert(candidates.end(), local.begin(), local.end());
        else
            overflow = true;
    };

    {
        std::vector<std::thread> pool;
        for (int i = 0; i < threads; i++) pool.emplace_back(worker);
        for (auto& t : pool) t.join();
    }
    result.bytes_scanned = scanned.load();
    result.candidates_seen = (i64)candidates.size();
    if (overflow.load())
        result.error = "signature candidate limit reached — results are partial; narrow the "
                       "category filter or scan a smaller region";

    if (prog.cancelled()) {
        result.ok = true;
        result.elapsed_ms = nowMs() - t0;
        return result;
    }

    // ---- pass 2: validate, size and extract --------------------------------
    prog.setPhase("validating and extracting");
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) {
                  if (a.offset != b.offset) return a.offset < b.offset;
                  return a.priority > b.priority;      // most specific spec first
              });
    // Units overlap so a signature fully inside a shared window is reported by
    // both neighbours; drop the exact duplicates before anything else.
    {
        std::vector<Candidate> unique;
        unique.reserve(candidates.size());
        for (const auto& c : candidates) {
            if (!unique.empty() && unique.back().offset == c.offset &&
                unique.back().spec == c.spec)
                continue;
            unique.push_back(c);
        }
        candidates = std::move(unique);
    }

    // Offsets of every candidate, used to bound formats that cannot state their
    // own length: a file ends no later than where the next one begins.
    std::vector<i64> starts;
    starts.reserve(candidates.size());
    for (const auto& c : candidates)
        if (starts.empty() || starts.back() != c.offset) starts.push_back(c.offset);

    std::unordered_set<std::string> seenHashes;
    std::map<std::string, int> perFormatCount;
    i64 acceptedEnd = -1;             // end of the most recently accepted file
    i64 acceptedStart = -1;
    bool acceptedValidated = false;   // only a structurally verified file masks others

    prog.set(0, (i64)candidates.size());
    ByteSource src(disk, result.image_size);

    for (size_t ci = 0; ci < candidates.size() && !prog.cancelled(); ci++) {
        if ((ci & 1023) == 0) prog.set((i64)ci, (i64)candidates.size());
        if ((i64)result.files.size() >= opt.max_files) break;

        const Candidate& cand = candidates[ci];
        const CarveSpec& spec = *specs[(size_t)cand.spec];
        const i64 off = cand.offset;

        // Skip anything that starts inside a file we already recovered — but
        // only when that file's structure was actually verified. A guessed
        // extent must never suppress a real file.
        if (acceptedValidated && off >= acceptedStart && off < acceptedEnd) {
            result.rejected++;
            continue;
        }

        i64 avail = result.image_size - off;
        if (avail < spec.min_size) { result.rejected++; continue; }
        i64 cap = std::min(spec.max_size, avail);
        cap = std::min(cap, opt.max_file_size);
        if (cap < spec.min_size) { result.rejected++; continue; }

        if (opt.validate && !confirmMatches(disk, spec, off, cap)) { result.rejected++; continue; }

        // Determine the length.
        i64 size = -1;
        bool guessedSize = false;
        if (opt.validate && spec.validator) {
            size = spec.validator(src, off, cap, spec);
            if (size < 0) { result.rejected++; continue; }
        }
        if (size <= 0) {
            switch (spec.mode) {
                case SizeMode::Footer: {
                    i64 f = findFooter(disk, off, cap, spec.footer);
                    if (f > 0) size = f + spec.footer_extra;
                    break;
                }
                default: break;
            }
        }
        if (size <= 0) {
            // No self-describing length: bound the file by the next signature.
            // The bound is never stretched past nextStart — a real file lives
            // where the next signature sits and would otherwise be swallowed.
            auto it = std::upper_bound(starts.begin(), starts.end(), off);
            i64 nextStart = (it != starts.end()) ? *it : result.image_size;
            i64 bound = nextStart - off;
            if (bound > cap) bound = cap;
            if (bound < spec.min_size) { result.rejected++; continue; }
            size = trimTrailingZeros(disk, off, bound);
            guessedSize = true;
            if (size < spec.min_size) { result.rejected++; continue; }
        }

        bool sizeClamped = false;
        if (size > cap) { size = cap; sizeClamped = true; }
        if (size < spec.min_size) { result.rejected++; continue; }
        if (size < opt.min_file_size) { result.rejected++; continue; }

        // Entropy screen: rejects both random noise that happens to contain a
        // signature and, for text formats, binary garbage.
        double entropy = 0;
        {
            i64 probeLen = std::min<i64>(size, 64 * 1024);
            auto probe = disk.readBlock((u64)off, probeLen);
            if (probe.empty()) { result.rejected++; continue; }
            entropy = shannonEntropy(probe.data(), probe.size());
            // Near-zero entropy means the region is a single repeated byte —
            // free space, not a file. Without this a weak signature can validate
            // a multi-megabyte run of zeroes and mask every real file behind it.
            if (entropy < 0.02 && probe.size() >= 512) { result.rejected++; continue; }
            if (spec.min_entropy >= 0 && entropy < spec.min_entropy) { result.rejected++; continue; }
            if (spec.max_entropy >= 0 && entropy > spec.max_entropy) { result.rejected++; continue; }
            if (spec.mode == SizeMode::Text && !looksLikeText(probe.data(), probe.size(), 0.85)) {
                result.rejected++;
                continue;
            }
        }

        // Stream the file out, hashing as we go.
        MD5 md5;
        SHA1 sha1;
        std::string outPath;
        FILE* fp = nullptr;
        if (opt.write_files) {
            std::string dir = joinPath(joinPath(opt.output_dir, spec.category), spec.ext);
            if (!makeDirs(dir)) {
                result.error = "cannot create output directory: " + dir;
                break;
            }
            int idx = ++perFormatCount[spec.name];
            char name[256];
            snprintf(name, sizeof(name), "%s_%05d.%s", safeFormatName(spec.name).c_str(), idx,
                     spec.ext.c_str());
            outPath = joinPath(dir, name);
            fp = fopen(outPath.c_str(), "wb");
            if (!fp) { result.rejected++; continue; }
        }

        i64 written = 0;
        bool readError = false;
        {
            const i64 kChunk = 4 * 1024 * 1024;
            while (written < size) {
                i64 want = std::min(kChunk, size - written);
                auto chunk = disk.readBlock((u64)(off + written), want);
                if (chunk.empty()) { readError = true; break; }
                if (opt.compute_hashes) {
                    md5.update(chunk.data(), chunk.size());
                    sha1.update(chunk.data(), chunk.size());
                }
                if (fp) fwrite(chunk.data(), 1, chunk.size(), fp);
                written += (i64)chunk.size();
                if ((i64)chunk.size() < want) { readError = true; break; }
            }
        }
        if (fp) fclose(fp);
        if (!outPath.empty()) adoptOwnership(outPath);
        if (written <= 0 || (readError && written < spec.min_size)) {
            if (!outPath.empty()) ::remove(outPath.c_str());
            result.rejected++;
            continue;
        }

        std::string digest;
        if (opt.compute_hashes) digest = md5.hex();
        else {
            // Cheap content key when hashing is disabled.
            auto head = disk.readBlock((u64)off, std::min<i64>(written, 8192));
            u64 h = 1469598103934665603ull;
            for (u8 b : head) { h ^= b; h *= 1099511628211ull; }
            digest = std::to_string(h);
        }
        std::string key = digest + ":" + std::to_string(written);
        if (opt.dedup && !seenHashes.insert(key).second) {
            if (!outPath.empty()) ::remove(outPath.c_str());
            result.duplicates++;
            // Still mark the range consumed so overlapping candidates are skipped.
            acceptedStart = off;
            acceptedEnd = off + written;
            acceptedValidated = true;
            continue;
        }

        CarvedFile cf;
        cf.format = spec.name;
        cf.ext = spec.ext;
        cf.category = spec.category;
        cf.offset = off;
        cf.size = written;
        cf.file = outPath;
        cf.entropy = entropy;
        cf.validated = (spec.validator != nullptr && opt.validate) && !guessedSize;
        cf.whole_file = cf.validated && spec.whole_file;
        cf.truncated = readError || written < size;
        cf.confidence = cf.validated ? (cf.truncated ? 0.6 : 1.0) : 0.5;
        if (opt.compute_hashes) { cf.md5 = digest; cf.sha1 = sha1.hex(); }
        cf.extents.push_back(Extent(off, written));

        result.by_format[spec.name]++;
        result.by_category[spec.category]++;
        result.files.push_back(std::move(cf));
        prog.setFound((i64)result.files.size());

        acceptedStart = off;
        acceptedEnd = off + written;
        acceptedValidated = cf.validated && !cf.truncated;
    }

    // ---- optional loose-text pass -----------------------------------------
    if (opt.text_carving && !prog.cancelled() && (i64)result.files.size() < opt.max_files) {
        prog.setPhase("recovering loose text");
        std::vector<std::pair<i64, i64>> claimed;
        claimed.reserve(result.files.size());
        for (const auto& f : result.files) claimed.emplace_back(f.offset, f.offset + f.size);
        std::sort(claimed.begin(), claimed.end());
        auto isClaimed = [&](i64 o) {
            auto it = std::upper_bound(claimed.begin(), claimed.end(), std::make_pair(o, (i64)0));
            if (it == claimed.begin()) return false;
            --it;
            return o < it->second;
        };

        const i64 kMinRun = 256;
        const i64 kChunk = 4 * 1024 * 1024;
        int textIdx = 0;
        for (const auto& region : regions) {
            for (i64 pos = 0; pos < region.length && !prog.cancelled(); pos += kChunk) {
                if ((i64)result.files.size() >= opt.max_files) break;
                i64 want = std::min(kChunk, region.length - pos);
                auto buf = disk.readBlock((u64)(region.offset + pos), want);
                if (buf.empty()) break;
                size_t i = 0;
                while (i < buf.size()) {
                    u8 c = buf[i];
                    bool printable = (c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r';
                    if (!printable) { i++; continue; }
                    size_t j = i;
                    while (j < buf.size()) {
                        u8 d = buf[j];
                        bool p = (d >= 0x20 && d < 0x7F) || d == '\t' || d == '\n' || d == '\r';
                        if (!p) break;
                        j++;
                    }
                    i64 runLen = (i64)(j - i);
                    i64 absOff = region.offset + pos + (i64)i;
                    if (runLen >= kMinRun && !isClaimed(absOff)) {
                        std::string outPath;
                        if (opt.write_files) {
                            std::string dir = joinPath(joinPath(opt.output_dir, "text"), "txt");
                            makeDirs(dir);
                            char name[128];
                            snprintf(name, sizeof(name), "text_%05d.txt", ++textIdx);
                            outPath = joinPath(dir, name);
                            FILE* fp = fopen(outPath.c_str(), "wb");
                            if (fp) { fwrite(buf.data() + i, 1, (size_t)runLen, fp); fclose(fp); }
                            adoptOwnership(outPath);
                        }
                        CarvedFile cf;
                        cf.format = "TEXT_RUN";
                        cf.ext = "txt";
                        cf.category = "text";
                        cf.offset = absOff;
                        cf.size = runLen;
                        cf.file = outPath;
                        cf.confidence = 0.3;
                        cf.entropy = shannonEntropy(buf.data() + i, (size_t)runLen);
                        if (opt.compute_hashes) cf.md5 = md5Hex(buf.data() + i, (size_t)runLen);
                        cf.extents.push_back(Extent(absOff, runLen));
                        result.by_format["TEXT_RUN"]++;
                        result.by_category["text"]++;
                        result.files.push_back(std::move(cf));
                        if ((i64)result.files.size() >= opt.max_files) break;
                    }
                    i = j + 1;
                }
            }
        }
    }

    result.files_recovered = (i64)result.files.size();
    result.elapsed_ms = nowMs() - t0;
    result.ok = true;
    prog.setPhase("done");
    return result;
}

}  // namespace ghost
