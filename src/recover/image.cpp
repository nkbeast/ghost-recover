// GHOST//RECOVER — ddrescue-style disk imaging.
//
// Recovering directly from a failing drive makes it fail faster. This copies
// the device to an image first, reading large blocks on the good pass and
// retrying only the bad areas sector by sector, keeping a resumable map of what
// has been read so an interrupted clone can be continued.
#include "ghost/recover.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <unistd.h>

namespace ghost {

namespace {

struct MapEntry {
    i64 offset = 0;
    i64 length = 0;
    char status = '?';    // '+' done, '-' failed, '?' untried
};

std::vector<MapEntry> loadMap(const std::string& path) {
    std::vector<MapEntry> out;
    std::ifstream f(path);
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        std::istringstream ss(line);
        MapEntry e;
        std::string status;
        if (!(ss >> e.offset >> e.length >> status)) continue;
        e.status = status.empty() ? '?' : status[0];
        out.push_back(e);
    }
    return out;
}

void saveMap(const std::string& path, const std::vector<MapEntry>& map) {
    if (path.empty()) return;
    std::ofstream f(path, std::ios::trunc);
    if (!f) return;
    f << "# ghost-recover image map: offset length status (+ done, - failed, ? untried)\n";
    for (const auto& e : map) f << e.offset << ' ' << e.length << ' ' << e.status << '\n';
}

void markRange(std::vector<MapEntry>& map, i64 offset, i64 length, char status) {
    if (length <= 0) return;
    if (!map.empty()) {
        MapEntry& last = map.back();
        if (last.status == status && last.offset + last.length == offset) {
            last.length += length;
            return;
        }
    }
    map.push_back({offset, length, status});
}

}  // namespace

ImageResult createImage(DiskReader& disk, const ImageOptions& opt, Progress& prog) {
    ImageResult res;
    const i64 t0 = nowMs();
    res.output_path = opt.output_path;

    if (opt.output_path.empty()) {
        res.error = "no output path given";
        return res;
    }
    if (writesBackOntoSource(opt.output_path, disk.path())) {
        res.error = "refusing to write the image onto " + disk.path() +
                    ", the device being imaged. Write the clone to a different disk.";
        return res;
    }
    if (!makeDirs(dirName(opt.output_path))) {
        res.error = "cannot create the output directory";
        return res;
    }

    i64 start = std::max<i64>(0, opt.start);
    i64 total = opt.length > 0 ? std::min(opt.length, disk.size() - start) : disk.size() - start;
    if (total <= 0) {
        res.error = "nothing to image (empty range)";
        return res;
    }

    int fd = ::open(opt.output_path.c_str(), O_WRONLY | O_CREAT | O_LARGEFILE, 0644);
    if (fd < 0) {
        res.error = "cannot open " + opt.output_path + " for writing: " + std::strerror(errno);
        return res;
    }
    // Pre-size so sparse writes land in the right place.
    if (::ftruncate(fd, (off_t)total) != 0) { /* non-fatal on some filesystems */ }

    std::vector<MapEntry> map;
    i64 resumeFrom = 0;
    if (!opt.mapfile.empty()) {
        map = loadMap(opt.mapfile);
        for (const auto& e : map)
            if (e.status == '+') resumeFrom = std::max(resumeFrom, e.offset + e.length);
        if (resumeFrom > 0)
            prog.setPhase("resuming at " + humanSize(resumeFrom));
    }

    const i64 blockSize = std::max<i64>(4096, opt.block_size);
    std::vector<u8> buf((size_t)blockSize);
    MD5 md5;
    bool hashValid = (resumeFrom == 0);

    prog.setPhase("imaging (pass 1: fast)");
    prog.set(resumeFrom, total);

    std::vector<std::pair<i64, i64>> badRanges;
    i64 pos = resumeFrom;
    const i64 sector = disk.sectorSize() ? disk.sectorSize() : 512;

    while (pos < total && !prog.cancelled()) {
        i64 want = std::min(blockSize, total - pos);
        i64 before = disk.badSectorCount();
        i64 got = disk.read((u64)(start + pos), buf.data(), want);
        bool hadError = disk.badSectorCount() > before;

        if (got <= 0) {
            // Whole block unreadable: record it and skip ahead.
            badRanges.emplace_back(pos, want);
            markRange(map, pos, want, '-');
            res.bytes_bad += want;
            pos += want;
            prog.set(pos, total);
            continue;
        }
        bool allZero = true;
        for (i64 i = 0; i < got && allZero; i++) if (buf[(size_t)i]) allZero = false;

        if (!(opt.sparse && allZero)) {
            i64 done = 0;
            while (done < got) {
                ssize_t n = ::pwrite(fd, buf.data() + done, (size_t)(got - done), (off_t)(pos + done));
                if (n <= 0) {
                    if (errno == EINTR) continue;
                    res.error = std::string("write failed: ") + std::strerror(errno);
                    break;
                }
                done += n;
            }
            if (!res.error.empty()) break;
        }
        if (hashValid && opt.verify) md5.update(buf.data(), (size_t)got);

        if (hadError) {
            badRanges.emplace_back(pos, got);
            markRange(map, pos, got, '-');
            res.bytes_bad += got;
        } else {
            markRange(map, pos, got, '+');
            res.bytes_copied += got;
        }
        pos += got;
        if ((pos & ((64 << 20) - 1)) < blockSize) {
            prog.set(pos, total);
            saveMap(opt.mapfile, map);
        }
    }
    prog.set(pos, total);
    saveMap(opt.mapfile, map);

    // ---- retry passes: sector by sector over the bad areas -----------------
    for (i64 pass = 0; pass < opt.retry_passes && !badRanges.empty() && !prog.cancelled(); pass++) {
        prog.setPhase("imaging (retry pass " + std::to_string(pass + 1) + ")");
        std::vector<std::pair<i64, i64>> stillBad;
        i64 recovered = 0;
        for (const auto& [rangeOff, rangeLen] : badRanges) {
            if (prog.cancelled()) break;
            for (i64 o = 0; o < rangeLen; o += sector) {
                i64 want = std::min(sector, rangeLen - o);
                i64 before = disk.badSectorCount();
                i64 got = disk.read((u64)(start + rangeOff + o), buf.data(), want);
                if (got == want && disk.badSectorCount() == before) {
                    ssize_t n = ::pwrite(fd, buf.data(), (size_t)got, (off_t)(rangeOff + o));
                    if (n == got) {
                        recovered += got;
                        markRange(map, rangeOff + o, got, '+');
                        continue;
                    }
                }
                stillBad.emplace_back(rangeOff + o, want);
            }
        }
        res.bytes_copied += recovered;
        res.bytes_bad -= recovered;
        badRanges.swap(stillBad);
        saveMap(opt.mapfile, map);
        if (recovered == 0) break;      // no progress; further passes will not help
    }

    ::fsync(fd);
    ::close(fd);
    adoptOwnership(opt.output_path);
    if (!opt.mapfile.empty()) adoptOwnership(opt.mapfile);

    // Coalesce the bad map for reporting.
    for (const auto& [o, l] : badRanges) {
        if (!res.bad_map.empty() && res.bad_map.back().offset + res.bad_map.back().length == o)
            res.bad_map.back().length += l;
        else
            res.bad_map.push_back(Extent(o, l));
    }
    res.bad_regions = (i64)res.bad_map.size();
    res.elapsed_ms = nowMs() - t0;
    if (res.elapsed_ms > 0)
        res.rate_mb_s = (double)res.bytes_copied / (1024.0 * 1024.0) / (res.elapsed_ms / 1000.0);
    if (opt.verify && hashValid && res.bytes_bad == 0) res.md5 = md5.hex();
    res.ok = res.error.empty() && res.bytes_copied > 0;
    if (!res.ok && res.error.empty()) res.error = "no data could be read from the source";
    prog.setPhase("done");
    return res;
}

}  // namespace ghost
