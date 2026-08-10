// GHOST//RECOVER — writing recovered files out.
//
// The old recoverFiles() read a single (offset,size) range per file, which
// silently corrupted every fragmented file, wrote everything into one flat
// directory, dropped names that collided, and produced no record of what came
// from where. This walks each file's extent list, rebuilds the directory tree,
// decompresses block-compressed sources, restores timestamps, and writes a
// manifest so the recovery is auditable.
#include "ghost/recover.h"

#include "ghost/json.h"
#include "ghost/util.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <unordered_set>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef GHOST_HAVE_ZLIB
#include <zlib.h>
#endif

namespace ghost {

namespace {

#ifdef GHOST_HAVE_ZLIB
bool inflateInto(const u8* src, size_t srcLen, std::vector<u8>& out) {
    z_stream zs{};
    if (inflateInit(&zs) != Z_OK) return false;
    zs.next_in = const_cast<Bytef*>(src);
    zs.avail_in = (uInt)srcLen;
    size_t base = out.size();
    out.resize(base + srcLen * 4 + 4096);
    size_t total = base;
    int ret;
    while (true) {
        zs.next_out = out.data() + total;
        zs.avail_out = (uInt)(out.size() - total);
        ret = inflate(&zs, Z_NO_FLUSH);
        total = out.size() - zs.avail_out;
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK) { inflateEnd(&zs); out.resize(base); return false; }
        if (zs.avail_out == 0) {
            if (out.size() > base + 512u * 1024 * 1024) { inflateEnd(&zs); out.resize(base); return false; }
            out.resize(out.size() * 2);
        } else if (zs.avail_in == 0) {
            break;
        }
    }
    inflateEnd(&zs);
    out.resize(total);
    return true;
}
#endif

void applyTimes(const std::string& path, i64 mtime, i64 atime) {
    if (mtime <= 0 && atime <= 0) return;
    struct timeval tv[2];
    tv[0].tv_sec = (time_t)(atime > 0 ? atime : mtime);
    tv[0].tv_usec = 0;
    tv[1].tv_sec = (time_t)(mtime > 0 ? mtime : atime);
    tv[1].tv_usec = 0;
    ::utimes(path.c_str(), tv);
}

std::string csvEscape(const std::string& s) {
    bool needQuotes = s.find_first_of(",\"\n\r") != std::string::npos;
    if (!needQuotes) return s;
    std::string o = "\"";
    for (char c : s) {
        if (c == '"') o += "\"\"";
        else o += c;
    }
    o += '"';
    return o;
}

}  // namespace

// ---------------------------------------------------------------------------
std::vector<u8> readFileData(DiskReader& disk, const RecoveredFile& f, i64 maxBytes) {
    if (!f.resident.empty()) {
        std::vector<u8> out = f.resident;
        if (f.size > 0 && (i64)out.size() > f.size) out.resize((size_t)f.size);
        if (maxBytes > 0 && (i64)out.size() > maxBytes) out.resize((size_t)maxBytes);
        return out;
    }
    std::vector<u8> out;
    i64 budget = maxBytes > 0 ? maxBytes : (f.size > 0 ? f.size : 0);
    if (budget <= 0) {
        for (const auto& e : f.extents) budget += e.length;
    }
    if (budget <= 0) return out;
    out.reserve((size_t)std::min<i64>(budget, 64 * 1024 * 1024));

    for (size_t ei = 0; ei < f.extents.size(); ei++) {
        const Extent& e = f.extents[ei];
        const bool isTailFragment = (f.fragment_offset >= 0 && ei + 1 == f.extents.size());
        if (!isTailFragment && (i64)out.size() >= budget) break;
        i64 want = isTailFragment ? e.length : std::min(e.length, budget - (i64)out.size());
        if (e.sparse) {
            out.insert(out.end(), (size_t)want, 0);
            continue;
        }
        auto chunk = disk.readBlock((u64)e.offset, want);
        std::vector<u8> decoded;
        const std::vector<u8>* payload = &chunk;
#ifdef GHOST_HAVE_ZLIB
        if (f.codec == "zlib-block") {
            if (!inflateInto(chunk.data(), chunk.size(), decoded)) continue;
            payload = &decoded;
        }
#endif
        if (isTailFragment) {
            size_t start = (size_t)f.fragment_offset;
            size_t len = (size_t)f.fragment_length;
            if (start >= payload->size()) continue;
            len = std::min(len, payload->size() - start);
            out.insert(out.end(), payload->begin() + start, payload->begin() + start + len);
            continue;
        }
        out.insert(out.end(), payload->begin(), payload->end());
        if ((i64)chunk.size() < want) break;
    }
    if (f.size > 0 && (i64)out.size() > f.size && f.codec.empty()) out.resize((size_t)f.size);
    return out;
}

// ---------------------------------------------------------------------------
ExtractResult extractFiles(DiskReader& disk, const std::vector<RecoveredFile>& files,
                           const ExtractOptions& opt, Progress& prog) {
    ExtractResult res;
    res.output_dir = opt.output_dir;

    if (opt.output_dir.empty()) {
        res.error = "no output directory given";
        return res;
    }
    if (writesBackOntoSource(opt.output_dir, disk.path())) {
        res.error = "refusing to write recovered files onto " + disk.path() +
                    ", the device they are being recovered from — doing so overwrites the "
                    "free space that still holds the rest of the data. Choose a destination "
                    "on a different disk.";
        return res;
    }
    if (!makeDirs(opt.output_dir)) {
        res.error = "cannot create output directory: " + opt.output_dir;
        return res;
    }

    std::unordered_set<u64> wanted(opt.only_ids.begin(), opt.only_ids.end());
    const bool filterIds = !wanted.empty();

    std::vector<const RecoveredFile*> todo;
    todo.reserve(files.size());
    for (const auto& f : files) {
        if (f.is_dir) continue;
        if (filterIds && !wanted.count(f.id)) continue;
        if (opt.skip_zero_size && f.dataBytes() == 0) continue;
        todo.push_back(&f);
    }

    prog.setPhase("extracting files");
    prog.set(0, (i64)todo.size());

    struct ManifestRow {
        std::string path, source, method, md5, sha1;
        i64 size = 0, recovered = 0, offset = 0;
        double confidence = 0;
        bool deleted = false;
        bool undecoded = false;
    };
    std::vector<ManifestRow> manifest;
    manifest.reserve(todo.size());

    std::unordered_set<std::string> usedPaths;
    i64 index = 0;

    for (const RecoveredFile* fp : todo) {
        if (prog.cancelled()) break;
        prog.set(++index, (i64)todo.size());
        const RecoveredFile& f = *fp;

        // Build the destination path.
        std::string rel;
        if (opt.preserve_paths && !f.path.empty()) {
            rel = sanitizeRelPath(f.path);
        }
        if (rel.empty()) rel = sanitizeFilename(f.name.empty() ? ("file_" + std::to_string(f.id))
                                                               : f.name);
        std::string dest = joinPath(opt.output_dir, rel);
        if (!makeDirs(dirName(dest))) {
            res.files_failed++;
            res.failures.push_back(rel + ": cannot create directory");
            continue;
        }
        if (!opt.overwrite && (fileExists(dest) || usedPaths.count(dest)))
            dest = uniquePath(dirName(dest), baseName(dest));
        usedPaths.insert(dest);

        // Stream it out.
        FILE* out = fopen(dest.c_str(), "wb");
        if (!out) {
            res.files_failed++;
            res.failures.push_back(rel + ": cannot open for writing");
            continue;
        }

        MD5 md5;
        SHA1 sha1;
        i64 written = 0;
        bool failed = false;
        i64 limit = opt.max_file_size;

        auto emit = [&](const u8* data, size_t len) {
            if (limit > 0 && written + (i64)len > limit) len = (size_t)std::max<i64>(0, limit - written);
            if (!len) return;
            if (opt.compute_hashes) { md5.update(data, len); sha1.update(data, len); }
            if (fwrite(data, 1, len, out) != len) failed = true;
            written += (i64)len;
        };

        if (!f.resident.empty()) {
            size_t n = f.resident.size();
            if (f.size > 0 && (i64)n > f.size) n = (size_t)f.size;
            emit(f.resident.data(), n);
        } else {
            const i64 kChunk = 4 * 1024 * 1024;
            i64 remaining = (f.size > 0 && f.codec.empty()) ? f.size : -1;
            static const std::vector<u8> kZeros(1 << 20, 0);
            for (size_t ei = 0; ei < f.extents.size(); ei++) {
                const Extent& e = f.extents[ei];
                const bool isTailFragment =
                    (f.fragment_offset >= 0 && ei + 1 == f.extents.size());
                if (failed || (limit > 0 && written >= limit)) break;
                if (remaining == 0 && !isTailFragment) break;
                i64 take = e.length;
                if (remaining > 0 && !isTailFragment) take = std::min(take, remaining);
                if (e.sparse) {
                    i64 left = take;
                    while (left > 0 && !failed) {
                        i64 n = std::min<i64>(left, (i64)kZeros.size());
                        emit(kZeros.data(), (size_t)n);
                        left -= n;
                    }
                    if (remaining > 0) remaining -= take;
                    continue;
                }
                i64 pos = 0;
                while (pos < take && !failed) {
                    i64 want = std::min(kChunk, take - pos);
                    auto chunk = disk.readBlock((u64)(e.offset + pos), want);
                    if (chunk.empty()) break;
                    std::vector<u8> decoded;
                    const std::vector<u8>* payload = &chunk;
#ifdef GHOST_HAVE_ZLIB
                    if (f.codec == "zlib-block") {
                        if (!inflateInto(chunk.data(), chunk.size(), decoded)) { pos = take; break; }
                        payload = &decoded;
                        pos = take;   // one extent == one independently coded block
                    }
#endif
                    if (isTailFragment) {
                        size_t start = (size_t)f.fragment_offset;
                        if (start < payload->size()) {
                            size_t len = std::min((size_t)f.fragment_length,
                                                  payload->size() - start);
                            emit(payload->data() + start, len);
                        }
                        pos = take;
                        break;
                    }
                    emit(payload->data(), payload->size());
                    if (payload == &chunk) pos += (i64)chunk.size();
                    if ((i64)chunk.size() < want) break;
                }
                if (remaining > 0 && !isTailFragment) remaining -= take;
            }
        }
        fclose(out);

        if (failed || written == 0) {
            ::remove(dest.c_str());
            res.files_failed++;
            res.failures.push_back(rel + (failed ? ": write error" : ": no readable data"));
            continue;
        }

        if (opt.preserve_times) applyTimes(dest, f.mtime, f.atime);
        adoptOwnership(dest);
        res.files_written++;
        // A file the filesystem stores compressed, in a codec this engine
        // cannot decode, has just been written out as raw compressed clusters.
        // It is on disk and the right size, which is exactly why silence here
        // would be worse than a failure.
        if (f.is_compressed && f.codec.empty()) {
            res.files_undecoded++;
            if (res.undecoded.size() < 500) res.undecoded.push_back(rel);
        }
        res.bytes_written += written;

        if (opt.write_manifest) {
            ManifestRow row;
            row.path = dest.substr(std::min(dest.size(), opt.output_dir.size() + 1));
            row.source = f.path.empty() ? f.name : f.path;
            row.method = f.method;
            row.size = f.size;
            row.recovered = written;
            row.offset = f.extents.empty() ? 0 : f.extents.front().offset;
            row.confidence = f.confidence;
            row.deleted = f.is_deleted;
            row.undecoded = f.is_compressed && f.codec.empty();
            if (opt.compute_hashes) { row.md5 = md5.hex(); row.sha1 = sha1.hex(); }
            manifest.push_back(std::move(row));
        }
    }

    // ---- manifests --------------------------------------------------------
    if (opt.write_manifest && !manifest.empty()) {
        std::string csvPath = joinPath(opt.output_dir, "ghost-manifest.csv");
        std::ofstream csv(csvPath);
        if (csv) {
            csv << "output_path,source_path,recovery_method,logical_size,bytes_written,"
                   "device_offset,deleted,confidence,still_compressed,md5,sha1\n";
            for (const auto& r : manifest) {
                csv << csvEscape(r.path) << ',' << csvEscape(r.source) << ','
                    << csvEscape(r.method) << ',' << r.size << ',' << r.recovered << ','
                    << r.offset << ',' << (r.deleted ? "yes" : "no") << ','
                    << r.confidence << ',' << (r.undecoded ? "yes" : "no") << ','
                    << r.md5 << ',' << r.sha1 << '\n';
            }
        }
        json::Writer w;
        w.beginObject();
        w.kv("source_device", disk.path());
        w.kv("window_offset", (i64)disk.base());
        w.kv("window_size", disk.size());
        w.kv("files_written", (i64)res.files_written);
        w.kv("bytes_written", res.bytes_written);
        w.key("files").beginArray();
        for (const auto& r : manifest) {
            w.beginObject();
            w.kv("output_path", r.path);
            w.kv("source_path", r.source);
            w.kv("method", r.method);
            w.kv("logical_size", r.size);
            w.kv("bytes_written", r.recovered);
            w.kv("device_offset", r.offset);
            w.kv("deleted", r.deleted);
            w.kv("confidence", r.confidence);
            if (r.undecoded) w.kv("still_compressed", true);
            if (!r.md5.empty()) w.kv("md5", r.md5);
            if (!r.sha1.empty()) w.kv("sha1", r.sha1);
            w.endObject();
        }
        w.endArray();
        w.endObject();
        std::ofstream js(joinPath(opt.output_dir, "ghost-manifest.json"));
        if (js) js << w.str();
        js.close();
        adoptOwnership(csvPath);
        adoptOwnership(joinPath(opt.output_dir, "ghost-manifest.json"));
    }

    res.ok = res.files_written > 0 || todo.empty();
    if (!res.ok && res.error.empty())
        res.error = "no files could be written — check that the extents are readable and that "
                    "the output directory is writable";
    return res;
}

// ---------------------------------------------------------------------------
ExtractResult recoverVolume(DiskReader& disk, const std::string& fsId, const ScanOptions& sopt,
                            const ExtractOptions& eopt, Progress& prog) {
    ExtractResult res;
    ScanResult scan = scanVolume(disk, fsId, sopt, prog);
    if (!scan.ok) {
        res.error = scan.error.empty() ? "filesystem scan failed" : scan.error;
        return res;
    }
    return extractFiles(disk, scan.files, eopt, prog);
}

// ---------------------------------------------------------------------------
SaveResult saveBytes(const std::string& outputDir, const std::string& filename,
                     const std::vector<u8>& data) {
    SaveResult r;
    if (!makeDirs(outputDir)) {
        r.error = "cannot create output directory: " + outputDir;
        return r;
    }
    std::string path = uniquePath(outputDir, filename.empty() ? "recovered.bin" : filename);
    FILE* fp = fopen(path.c_str(), "wb");
    if (!fp) {
        r.error = "cannot open output file: " + path;
        return r;
    }
    size_t n = data.empty() ? 0 : fwrite(data.data(), 1, data.size(), fp);
    bool ok = (n == data.size());
    if (fclose(fp) != 0) ok = false;
    if (!ok) {
        ::remove(path.c_str());
        r.error = "write failed (disk full?)";
        return r;
    }
    adoptOwnership(path);
    r.ok = true;
    r.path = path;
    r.size = (i64)data.size();
    return r;
}

}  // namespace ghost
