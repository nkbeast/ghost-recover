// GHOST RECOVER — carving engine.
//
// Two passes. The first sweeps the target with a single Aho-Corasick automaton
// across as many worker threads as the machine has cores and records candidate
// offsets. The second validates those candidates in parallel (each worker on
// its own reader clone), then walks the survivors in disk order, decides each
// one's length, and streams the file out while hashing it. Accept/reject,
// masking and dedup stay serial in disk order because they are ordered
// decisions; only the read-only validation work is parallel.
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
// read boundary is still found. The search is capped: footer-based lengths are
// a heuristic for formats without a self-describing walker, and on a flood
// disk the junk candidates that never find their footer would otherwise scan
// the whole 4 GiB cap each — that single cost is what made a big carve's
// validation phase crawl. A real file whose footer lies beyond the cap still
// gets carved, just via the next-signature bound instead.
i64 findFooter(DiskReader& disk, i64 start, i64 limit, const std::vector<u8>& footer) {
    if (footer.empty()) return -1;
    constexpr i64 kFooterCap = 128LL * 1024 * 1024;
    if (limit > kFooterCap) limit = kFooterCap;
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
        if (zeros < (i64)tail.size()) return size - examined - zeros;
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
        i64 end = result.image_size;
        if (opt.length > 0) {
            // start + opt.length must not overflow i64 even for hostile input.
            end = (start > result.image_size || opt.length > result.image_size - start)
                      ? result.image_size
                      : start + opt.length;
        }
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
    // Small boxes cannot afford one full-speed reader per core: scale the
    // worker count with installed RAM (1 GiB -> 2, 4 GiB -> 8, 16 GiB -> 16).
    {
        const i64 ramGB = systemRamKB() / (1024 * 1024);
        int cap = ramGB > 0 ? (int)std::min<i64>(16, std::max<i64>(2, ramGB * 2)) : 16;
        if (threads > cap) threads = cap;
    }

    // Carve workers read sequentially in 4 MiB chunks that bypass the block
    // cache entirely, so a big per-reader cache is pure waste here. Keep a
    // small one (validators and footer scans still get locality) so 16 workers
    // cost ~32 MiB instead of ~512 MiB.
    disk.setCacheSize(2 * 1024 * 1024);

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
    // See the RAM-scaling comment below: the cap is lowered on small boxes so
    // candidates + validated array + the resident scan result fit in RAM.
    size_t kMaxCandidates = 2 * 1000 * 1000;
    {
        const i64 ramGB = std::max<i64>(1, systemRamKB() / (1024 * 1024));
        size_t cap = (size_t)std::min<i64>(2LL * 1000 * 1000,
                                           std::max<i64>(500LL * 1000, 500LL * 1000 * ramGB));
        kMaxCandidates = cap;
    }

    // Regions a filesystem scan already accounts for (a deep job): signature
    // hits inside them would be walked, validated and streamed only to be
    // dropped as duplicates by the merge — on a real disk that meant reading
    // every live file's full span twice. Skip them at hit time.
    std::atomic<i64> skippedHits{0};
    if (getenv("GHOST_DEBUG_CARVE")) {
        i64 covered = 0;
        for (const auto& e : opt.skip_regions) covered += e.length;
        fprintf(stderr, "[carve] skipIndex regions=%zu covered=%lld bytes\n",
                opt.skip_regions.size(), (long long)covered);
    }
    struct SkipIndex {
        std::vector<i64> starts, ends;
        bool contains(i64 off) const {
            auto it = std::upper_bound(starts.begin(), starts.end(), off);
            if (it == starts.begin()) return false;
            size_t k = (size_t)(it - starts.begin()) - 1;
            return off < ends[k];
        }
    } skipIndex;
    if (!opt.skip_regions.empty()) {
        std::vector<std::pair<i64, i64>> spans;
        spans.reserve(opt.skip_regions.size());
        for (const auto& e : opt.skip_regions)
            if (e.length > 0) spans.push_back({e.offset, e.offset + e.length});
        std::sort(spans.begin(), spans.end());
        for (const auto& [s, e] : spans) {
            if (!skipIndex.starts.empty() && s <= skipIndex.ends.back()) {
                if (e > skipIndex.ends.back()) skipIndex.ends.back() = e;
            } else {
                skipIndex.starts.push_back(s);
                skipIndex.ends.push_back(e);
            }
        }
    }

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
                                 if (skipIndex.contains(fileOff)) return;
                                 skippedHits.fetch_add(1, std::memory_order_relaxed);
                                 if (sp->scan_filter) {
                                     i64 rel = hitOff - pos;
                                     if (rel >= 0 &&
                                         !sp->scan_filter(buf.data() + rel,
                                                          (i64)buf.size() - rel))
                                         return;
                                 }
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
    if (getenv("GHOST_DEBUG_CARVE"))
        fprintf(stderr, "[carve] done pass1: candidates=%zu skipped-by-scan=%lld overflow=%d\n",
                candidates.size(), (long long)skippedHits.load(), (int)overflow.load());
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

    // ---- pass 2: validate (parallel), then accept and stream out -----------
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

    // Validation is pure read work — structure walk, footer lookups, entropy
    // probe — so it parallelises across reader clones. Accept/reject, dedup and
    // the final stream-out must stay serial in disk order: the masking rule (a
    // verified file hides candidates inside it) and the whole-file dedup key
    // are inherently ordered decisions. Processing therefore alternates in
    // slabs: candidates are validated in parallel, then walked serially in
    // order. Candidates already contained by a *previously accepted* file are
    // skipped before any read — the masking rule says they are dead either
    // way, and on a full disk the contained majority makes validation the
    // expensive minority.
    struct Validated {
        i64 size = 0;
        i64 backscan = 0;          // bytes of the file before the signature
        double entropy = 0;
        bool valid = false;
        bool guessed = false;
        bool sizeClamped = false;
    };
    std::vector<Validated> validated(candidates.size());
    const size_t kGrain = 64;         // consecutive candidates per work claim

    auto examine = [&](size_t ci, const Candidate& cand, DiskReader& rd, ByteSource& src) {
        const CarveSpec& spec = *specs[(size_t)cand.spec];
        const i64 off = cand.offset;
        Validated& v = validated[ci];
        v.valid = false;

        i64 avail = result.image_size - off;
        static const bool dbg2 = getenv("GHOST_DEBUG_CARVE") != nullptr;
        if (avail < spec.min_size) {
            if (dbg2) fprintf(stderr, "[carve] reject %s off=%lld reason=avail%lld<min%lld\n",
                             spec.name.c_str(), (long long)off, (long long)avail, (long long)spec.min_size);
            return;
        }
        i64 cap = std::min(spec.max_size, avail);
        cap = std::min(cap, opt.max_file_size);
        if (cap < spec.min_size) {
            if (dbg2) fprintf(stderr, "[carve] reject %s off=%lld reason=cap%lld<min%lld\n",
                             spec.name.c_str(), (long long)off, (long long)cap, (long long)spec.min_size);
            return;
        }

        if (opt.validate && !confirmMatches(rd, spec, off, cap)) {
            if (dbg2) fprintf(stderr, "[carve] reject %s off=%lld reason=confirm\n",
                             spec.name.c_str(), (long long)off);
            return;
        }

        // Entropy bounds are screened BEFORE the length is determined: they
        // sample the same 64 KiB prefix either way, and rejecting junk early
        // skips the expensive part for the flood candidates that dominate a
        // big carve — a zero-filled region's signature hits, for example,
        // previously walked the whole window trimming zeros before the screen
        // rejected them. The text screen stays on the sized sample below.
        {
            i64 probeLen = std::min<i64>(avail, 64 * 1024);
            auto probe = rd.readBlock((u64)off, probeLen);
            if (probe.empty()) return;
            double entropy = shannonEntropy(probe.data(), probe.size());
            v.entropy = entropy;
            if (spec.min_entropy >= 0 && entropy < spec.min_entropy) {
                if (dbg2) fprintf(stderr, "[carve] reject %s off=%lld reason=entropy\n",
                                 spec.name.c_str(), (long long)off);
                return;
            }
            if (spec.max_entropy >= 0 && entropy > spec.max_entropy) {
                if (dbg2) fprintf(stderr, "[carve] reject %s off=%lld reason=entropy\n",
                                 spec.name.c_str(), (long long)off);
                return;
            }
        }

        // Determine the length.
        i64 size = -1;
        if (opt.validate && spec.validator) {
            i64 tV = nowMs();
            src.setBackscan(0);
            size = spec.validator(src, off, cap, spec);
            i64 dt = nowMs() - tV;
            if (dbg2 && dt >= 100)
                fprintf(stderr, "[carve] slow %s off=%lld took=%lldms\n",
                        spec.name.c_str(), (long long)off, (long long)dt);
            v.backscan = src.backscan();
            if (size < 0) {
                if (dbg2) fprintf(stderr, "[carve] reject %s off=%lld reason=validator\n",
                                 spec.name.c_str(), (long long)off);
                return;
            }
        }
        if (size > 0) {
            // Chain walkers without an end marker must not read into the next
            // file; the bound is applied in the serial pass once every
            // candidate's validation is known (only validated starts count).
        }
        if (size <= 0) {
            switch (spec.mode) {
                case SizeMode::Footer: {
                    i64 f = findFooter(rd, off, cap, spec.footer);
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
            size = trimTrailingZeros(rd, off, bound);
            v.guessed = true;
        }
        if (v.guessed && size > 0 && size < spec.min_size) {
            // The fallback shrank the candidate below the format minimum (a
            // footer hit near the start or a next signature right behind this
            // one): it is a false positive, not a short file. Exact sizes
            // returned by a walker are legitimate no matter how small.
            if (dbg2) fprintf(stderr, "[carve] reject %s off=%lld reason=fallback%lld<min%lld\n",
                             spec.name.c_str(), (long long)off, (long long)size,
                             (long long)spec.min_size);
            return;
        }

        if (size > cap) { size = cap; v.sizeClamped = true; }

        // Text screen on the sized sample (a small text file must not be
        // judged by whatever follows it on the disk).
        if (spec.mode == SizeMode::Text) {
            i64 probeLen = std::min<i64>(size, 64 * 1024);
            auto probe = rd.readBlock((u64)off, probeLen);
            if (probe.empty()) return;
            if (!looksLikeText(probe.data(), probe.size(), 0.85)) {
                if (dbg2) fprintf(stderr, "[carve] reject %s off=%lld reason=not-text\n",
                                 spec.name.c_str(), (long long)off);
                return;
            }
        }

        v.size = size;
        v.valid = true;
    };

    std::unordered_set<std::string> seenHashes;
    std::map<std::string, int> perFormatCount;
    i64 acceptedEnd = -1;             // end of the most recently accepted file
    i64 acceptedStart = -1;
    bool acceptedValidated = false;   // only a structurally verified file masks others

    // Progress runs 0..2n across the two phases so the bar is monotonic and
    // never fakes: validation drives [0, n), the serial walk continues [n, 2n).
    // Without this the validation phase — on a flood disk the bulk of the wall
    // time — sat at 0% and the walk restarted the bar from zero, so the UI
    // looked frozen or rewinding.
    const i64 progTotal = 2 * (i64)candidates.size();
    prog.set(0, progTotal);

    // Phase A: validate every candidate in parallel. Pure read work, so the
    // whole set goes at once (slabs only bound how many reads each worker
    // claims). No masking here: that decision belongs to the serial pass.
    {
        std::atomic<size_t> nextCand{0};
        std::atomic<size_t> validatedCount{0};
        std::vector<std::thread> pool;
        for (int i = 0; i < threads; i++)
            pool.emplace_back([&]() {
                auto reader = disk.clone();
                if (!reader) return;
                ByteSource src(*reader, result.image_size);
                while (!prog.cancelled()) {
                    size_t beg = nextCand.fetch_add(kGrain);
                    if (beg >= candidates.size()) break;
                    size_t end = std::min(beg + kGrain, candidates.size());
                    for (size_t ci = beg; ci < end; ci++)
                        examine(ci, candidates[ci], *reader, src);
                    validatedCount += end - beg;
                    prog.set((i64)validatedCount.load(), progTotal);
                }
            });
        for (auto& t : pool) t.join();
    }
    if (prog.cancelled()) return result;

    // Offsets of genuine candidates — only these may bound an end-less walker.
    // A junk signature hit (ICO/CUR/DER magic inside another file's payload)
    // never validated and must not truncate the file around it. A candidate
    // that WAS validated at an offset inside another validated candidate's
    // span is likewise not a real boundary: DER files are self-similar, so a
    // nested 30 81/30 82 sub-TLV inside a certificate validates as its own
    // little DER and, left in this list, clamps the real 4 KB certificate to
    // a 4-byte stub. The serial masking pass would hide it anyway.
    std::vector<i64> bounds;
    bounds.reserve(candidates.size());
    i64 coverEnd = -1;
    int coverPriority = 0;   // priority of the candidate that set coverEnd
    for (size_t ci = 0; ci < candidates.size(); ci++) {
        const Validated& v = validated[ci];
        if (!v.valid || v.size <= 0) continue;
        const i64 off = candidates[ci].offset;
        // A candidate that validates all the way to the disk end is a junk
        // signature hit (a header that computed a giant length and walked
        // through everything). Its span covers the whole rest of the disk, so
        // it must neither mask the real files behind it nor act as a boundary.
        if (off + v.size >= result.image_size) continue;
        if (bounds.empty() || bounds.back() != off) {
            const CarveSpec& sp = *specs[(size_t)candidates[ci].spec];
            if (off >= coverEnd) {
                bounds.push_back(off);
            } else if (off + v.size >= coverEnd && sp.priority > coverPriority) {
                // A start inside another validated span whose spec is stronger
                // than the walk covering it (MP3_ID3 inside a junk MP3_FRAME
                // walk that read through it) is a separate file and a genuine
                // boundary. Frame-sync noise of the same weak signature inside
                // a strong file ends at the same cover and stays excluded.
                bounds.push_back(off);
            }
            if (sp.validator) {
                if (off + v.size > coverEnd) {
                    coverEnd = off + v.size;
                    coverPriority = sp.priority;
                } else if (off + v.size == coverEnd && sp.priority > coverPriority) {
                    coverPriority = sp.priority;
                }
            }
        }
    }

    // Phase B: serial accept in disk order — masking envelopes (only a
    // structurally verified file hides candidates), the bound_to_next clamp,
    // whole-file dedup, and final stream-out are all ordered decisions.
    for (size_t ci = 0; ci < candidates.size(); ci++) {
        if (prog.cancelled()) break;
        if ((ci & 1023) == 0)
            prog.set((i64)candidates.size() + (i64)ci, progTotal);
        if ((i64)result.files.size() >= opt.max_files) break;

        const Candidate& cand = candidates[ci];
        const CarveSpec& spec = *specs[(size_t)cand.spec];
        const i64 off = cand.offset;
        const Validated& v = validated[ci];

        // Skip anything that starts inside a file we already recovered —
        // but only when that file's structure was actually verified. A
        // guessed extent must never suppress a real file.
        static const bool dbg = getenv("GHOST_DEBUG_CARVE") != nullptr;
        if (acceptedValidated && off >= acceptedStart && off < acceptedEnd) {
            if (dbg) fprintf(stderr, "[carve] masked %s off=%lld size=%lld by span [%lld,%lld)\n",
                             spec.name.c_str(), (long long)off, (long long)v.size,
                             (long long)acceptedStart, (long long)acceptedEnd);
            result.rejected++;
            continue;
        }
        if (!v.valid) { result.rejected++; continue; }
        // A walker whose computed size had to be clamped and lands on the
        // device end is a junk signature hit (a header that computed a giant
        // length), not a real file ending exactly at the end of the device —
        // the latter carries an exact, unclamped size. Accepting it would
        // carve garbage and mask every real file behind it.
        if (v.sizeClamped && off + v.size >= result.image_size) {
            if (dbg) fprintf(stderr, "[carve] reject %s off=%lld reason=disk-end-clamped\n",
                             spec.name.c_str(), (long long)off);
            result.rejected++;
            continue;
        }
        if (dbg) fprintf(stderr, "[carve] accept %s off=%lld size=%lld\n",
                         spec.name.c_str(), (long long)off, (long long)v.size);
        i64 size = v.size;
        if (size > 0 && spec.bound_to_next) {
            // Chain walkers without an end marker (MAT, pickles, DER, binary
            // plists, qcow/VHDX/VHD/VDI walks) read on into the next file.
            // The next genuine file start is the only honest boundary.
            auto bit = std::upper_bound(bounds.begin(), bounds.end(), off);
            if (bit != bounds.end()) {
                i64 bound_ = *bit - off;
                if (size > bound_) size = bound_;
            }
            // The bound can shrink a walker to a junk stub; below the format
            // minimum it is a false positive, not a short file.
            if (size < spec.min_size) {
                if (dbg) fprintf(stderr, "[carve] reject %s off=%lld reason=bound%lld<min%lld\n",
                                 spec.name.c_str(), (long long)off, (long long)size,
                                 (long long)spec.min_size);
                result.rejected++;
                continue;
            }
        }

        // Stream the file out, hashing as we go. A backscanned format's bytes
        // run from (off - backscan) to (off + size).
        const i64 carveStart = off - v.backscan;
        const i64 outLen = v.backscan + size;
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
        bool writeError = false;
        {
            const i64 kChunk = 4 * 1024 * 1024;
            while (written < outLen) {
                i64 want = std::min(kChunk, outLen - written);
                auto chunk = disk.readBlock((u64)(carveStart + written), want);
                if (chunk.empty()) { readError = true; break; }
                disk.adviseDrop((u64)(carveStart + written), (i64)chunk.size());
                if (opt.compute_hashes) {
                    md5.update(chunk.data(), chunk.size());
                    sha1.update(chunk.data(), chunk.size());
                }
                if (fp && fwrite(chunk.data(), 1, chunk.size(), fp) != chunk.size()) {
                    writeError = true;
                    break;
                }
                written += (i64)chunk.size();
                if ((i64)chunk.size() < want) { readError = true; break; }
            }
        }
        if (fp) fclose(fp);
        if (!outPath.empty()) adoptOwnership(outPath);
        if (written <= 0 || ((readError || writeError) && written < spec.min_size)) {
            if (!outPath.empty()) ::remove(outPath.c_str());
            result.rejected++;
            continue;
        }

        std::string digest;
        if (opt.compute_hashes) digest = md5.hex();
        else {
            // Cheap content key when hashing is disabled.
            auto head = disk.readBlock((u64)carveStart, std::min<i64>(written, 8192));
            u64 h = 1469598103934665603ull;
            for (u8 b : head) { h ^= b; h *= 1099511628211ull; }
            digest = std::to_string(h);
        }
        std::string key = digest + ":" + std::to_string(written);
        // The 8 KiB head + length key is far too weak to distinguish files, so
        // dedup is only safe when real hashes were computed.
        if (opt.dedup && opt.compute_hashes && !seenHashes.insert(key).second) {
            if (!outPath.empty()) ::remove(outPath.c_str());
            result.duplicates++;
            // Still mark the range consumed so overlapping candidates are skipped.
            acceptedStart = carveStart;
            acceptedEnd = carveStart + written;
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
        cf.entropy = v.entropy;
        cf.validated = (spec.validator != nullptr && opt.validate) && !v.guessed;
        cf.whole_file = cf.validated && spec.whole_file;
        cf.truncated = readError || writeError || written < size || v.sizeClamped;
        cf.confidence = cf.validated ? (cf.truncated ? 0.6 : 1.0) : 0.5;
        if (opt.compute_hashes) { cf.md5 = digest; cf.sha1 = sha1.hex(); }
        cf.extents.push_back(Extent(carveStart, written));

        if (opt.on_file) opt.on_file(cf);
        result.by_format[spec.name]++;
        result.by_category[spec.category]++;
        result.files.push_back(std::move(cf));
        prog.setFound((i64)result.files.size());

        acceptedStart = carveStart;
        acceptedEnd = carveStart + written;
        acceptedValidated = !v.guessed && !cf.truncated;
    }

    // ---- optional loose-text pass -----------------------------------------
    if (opt.text_carving && !prog.cancelled() && (i64)result.files.size() < opt.max_files) {
        prog.setPhase("recovering loose text");
        std::vector<std::pair<i64, i64>> claimed;
        claimed.reserve(result.files.size());
        for (const auto& f : result.files) {
            // The real byte span is [offset - backscan, offset + size); the
            // extents record it, the offset field only the signature position.
            const Extent& e = f.extents.empty() ? Extent(f.offset, f.size)
                                                : f.extents.front();
            claimed.emplace_back(e.offset, e.offset + e.length);
        }
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
