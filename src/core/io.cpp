#include "ghost/io.h"
#include "ghost/util.h"

#include <algorithm>
#include <cerrno>
#include <cstring>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ghost {

namespace {
constexpr i64    kCacheBlock   = 64LL * 1024;   // cache granularity
// Default cache: sized to the machine's RAM so a small box is not drowned by
// per-reader caches. 1 GiB -> 8 MiB, 16 GiB+ -> 32 MiB.
i64 defaultCacheBytes() {
    const i64 kb = systemRamKB();
    if (kb <= 0) return 32LL * 1024 * 1024;
    const i64 by = kb * 1024 / 128;
    return std::min<i64>(32LL * 1024 * 1024, std::max<i64>(4LL * 1024 * 1024, by));
}
// Reads at least this large skip the cache: sequential carving would otherwise
// evict the metadata blocks the filesystem drivers depend on.
constexpr i64 kCacheBypass  = kCacheBlock * 2;
constexpr i64 kMaxCacheBytes = 512LL * 1024 * 1024;

size_t roundUpPow2(size_t v) {
    if (v <= 1) return 1;
    constexpr size_t kTopBit = size_t(1) << (sizeof(size_t) * 8 - 1);
    if (v > kTopBit) return kTopBit;
    size_t p = 1;
    while (p < v) {
        if (p > kTopBit / 2) return kTopBit;
        p <<= 1;
    }
    return p;
}
}  // namespace

Progress& nullProgress() {
    static Progress p;
    return p;
}

const char* fileKindName(FileKind k) {
    switch (k) {
        case FileKind::Regular:   return "file";
        case FileKind::Directory: return "dir";
        case FileKind::Symlink:   return "symlink";
        case FileKind::Device:    return "device";
        case FileKind::Fifo:      return "fifo";
        case FileKind::Socket:    return "socket";
        default:                  return "other";
    }
}

// ---------------------------------------------------------------------------

DiskReader::DiskReader(std::string path) : path_(std::move(path)) {
    setCacheSize(defaultCacheBytes());
}

DiskReader::~DiskReader() { close(); }

void DiskReader::setCacheSize(i64 bytes) {
    cache_bytes_ = std::min<i64>(kMaxCacheBytes, std::max<i64>(kCacheBlock, bytes));
    size_t lines = (size_t)std::max<i64>(8, cache_bytes_ / kCacheBlock);
    lines = roundUpPow2(lines);
    cache_.assign(lines, CacheLine{});
    cache_mask_ = lines - 1;
}

void DiskReader::dropCache() {
    for (auto& l : cache_) { l.tag = ~0ull; l.valid = 0; }
}

void DiskReader::adviseDrop(u64 abs_off, i64 count) {
    if (fd_ < 0 || count <= 0) return;
    // Best effort: the kernel is free to ignore the hint.
    (void)::posix_fadvise(fd_, (off_t)abs_off, (off_t)count, POSIX_FADV_DONTNEED);
}

bool DiskReader::open(std::string* err) {
    close();
    fd_ = ::open(path_.c_str(), O_RDONLY | O_LARGEFILE);
    if (fd_ < 0) {
        if (err) *err = describeOpenFailure(path_);
        return false;
    }

    struct stat st{};
    if (fstat(fd_, &st) == 0) {
        is_raw_ = S_ISBLK(st.st_mode);
        if (S_ISREG(st.st_mode)) device_size_ = st.st_size;
    }

    if (is_raw_ || device_size_ == 0) {
        u64 sz = 0;
        if (ioctl(fd_, BLKGETSIZE64, &sz) == 0 && sz > 0) {
            device_size_ = (i64)sz;
        } else {
            const i64 end = lseek(fd_, 0, SEEK_END);
            if (end > 0) device_size_ = end;
        }
        int ss = 0;
        if (ioctl(fd_, BLKSSZGET, &ss) == 0 && ss >= 512) sector_size_ = ss;
    }

    if (device_size_ <= 0) {
        // Character devices and some pseudo-files report no size; probe by
        // seeking so at least sequential carving can proceed.
        i64 end = lseek(fd_, 0, SEEK_END);
        device_size_ = end > 0 ? end : 0;
    }

    base_ = 0;
    size_ = device_size_;
    clearHealth();
    dropCache();
    return true;
}

void DiskReader::close() {
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
}

std::unique_ptr<DiskReader> DiskReader::clone() const {
    auto d = std::make_unique<DiskReader>(path_);
    d->setCacheSize(cache_bytes_);
    if (!d->open(nullptr)) return nullptr;
    d->setWindow(base_, size_);
    return d;
}

void DiskReader::setWindow(u64 base, i64 length) {
    if ((i64)base > device_size_) base = (u64)device_size_;
    base_ = base;
    i64 avail = device_size_ - (i64)base;
    if (avail < 0) avail = 0;
    size_ = (length > 0) ? std::min(length, avail) : avail;
    dropCache();
}

void DiskReader::resetWindow() {
    base_ = 0;
    size_ = device_size_;
    dropCache();
}

void DiskReader::clearHealth() {
    bad_sectors_ = 0;
    bytes_read_  = 0;
    bad_regions_.clear();
}

void DiskReader::noteBad(u64 abs_off, i64 len) {
    bad_sectors_ += std::max<i64>(1, len / sector_size_);
    if (!bad_regions_.empty()) {
        Extent& last = bad_regions_.back();
        if (last.offset + last.length == (i64)abs_off) { last.length += len; return; }
    }
    if (bad_regions_.size() < 4096) bad_regions_.push_back(Extent((i64)abs_off, len));
}

i64 DiskReader::rawPread(u64 abs_off, u8* dst, i64 count) {
    i64 total = 0;
    while (total < count) {
        const ssize_t n = ::pread(fd_, dst + total, (size_t)(count - total), (off_t)(abs_off + total));
        if (n > 0) { total += n; continue; }
        if (n == 0) break;                      // clean EOF
        if (errno == EINTR) continue;
        // Hardware/medium error — fall back to a per-sector read so we salvage
        // everything around the bad spot instead of losing the whole request.
        const i64 got = degradedPread(abs_off + total, dst + total, count - total);
        total += got;
        break;
    }
    return total;
}

i64 DiskReader::degradedPread(u64 abs_off, u8* dst, i64 count) {
    // Multi-pass bad-block retry (ddrescue-style).
    //
    // Pass 0: native sector-size chunks  — fastest; recovers most data in one sweep.
    // Pass 1: 512-byte sub-sector chunks — only when sector_size_ > 512 (4Kn drives).
    // Pass 2: 1-byte chunks             — last resort; maximum salvage before zero-fill.
    //
    // Regions that fail in one pass are queued for the next smaller granularity.
    // Failed bytes are zero-filled immediately on queue so that `dst` is fully
    // initialised at all times — a later successful retry overwrites the zeros.
    struct Range { u64 off; i64 len; i64 dst_off; };
    std::vector<Range> pending = {{abs_off, count, 0}};

    const i64 ss           = sector_size_ > 0 ? sector_size_ : 512;
    const i64 pass_sizes[] = { ss, 512, 1 };
    const int num_passes   = 3;
    // When ss==512 the sector-size pass and the 512-byte pass are identical;
    // skip directly to 512-byte chunks to avoid a redundant sweep.
    const int first_pass   = (ss > 512) ? 0 : 1;

    i64 total = 0;   // high-water mark: bytes in dst that are initialised (data or zeros)

    for (int p = first_pass; p < num_passes; p++) {
        const i64  chunk_size = pass_sizes[p];
        const bool last_pass  = (p == num_passes - 1);
        std::vector<Range> next_pending;

        for (const auto& r : pending) {
            i64 done = 0;
            while (done < r.len) {
                const i64     try_len = std::min(chunk_size, r.len - done);
                const ssize_t n       = ::pread(fd_,
                                                dst + r.dst_off + done,
                                                (size_t)try_len,
                                                (off_t)(r.off + done));
                if (n > 0) {
                    done  += n;
                    total  = std::max(total, r.dst_off + done);
                } else if (n == 0) {
                    // EOF: zero-fill the remainder of this range so dst has no gaps.
                    std::memset(dst + r.dst_off + done, 0, (size_t)(r.len - done));
                    total = std::max(total, r.dst_off + done);
                    break;
                } else {
                    if (errno == EINTR) continue;
                    // Zero-fill immediately — a successful retry in the next pass
                    // overwrites these provisional zeros with real data.
                    std::memset(dst + r.dst_off + done, 0, (size_t)try_len);
                    if (last_pass) {
                        noteBad(r.off + done, try_len);
                    } else {
                        next_pending.push_back({r.off + done, try_len, r.dst_off + done});
                    }
                    done  += try_len;
                    total  = std::max(total, r.dst_off + done);
                }
            }
        }
        pending = std::move(next_pending);
        if (pending.empty()) break;
    }

    return total;
}

i64 DiskReader::read(u64 offset, void* buf, i64 count) {
    if (fd_ < 0 || count <= 0 || !buf) return 0;
    if ((i64)offset >= size_) return 0;
    if ((i64)offset + count > size_) count = size_ - (i64)offset;
    if (count <= 0) return 0;

    u8* dst = static_cast<u8*>(buf);
    const u64 abs = base_ + offset;

    if (count >= kCacheBypass || cache_.empty()) {
        const i64 n = rawPread(abs, dst, count);
        bytes_read_ += n;
        return n;
    }

    i64 done = 0;
    while (done < count) {
        const u64 a       = abs + (u64)done;
        const u64 blk     = a / (u64)kCacheBlock;
        const i64 within  = (i64)(a % (u64)kCacheBlock);
        const i64 want    = std::min(count - done, kCacheBlock - within);

        CacheLine& line = cache_[(size_t)blk & cache_mask_];
        if (line.tag != blk) {
            if ((i64)line.data.size() != kCacheBlock) line.data.resize((size_t)kCacheBlock);
            const i64 got = rawPread(blk * (u64)kCacheBlock, line.data.data(), kCacheBlock);
            line.tag   = blk;
            line.valid = got;
            bytes_read_ += got;
        }
        if (within >= line.valid) break;        // past end of device
        const i64 avail = std::min(want, line.valid - within);
        std::memcpy(dst + done, line.data.data() + within, (size_t)avail);
        done += avail;
        if (avail < want) break;
    }
    return done;
}

std::vector<u8> DiskReader::readBlock(u64 offset, i64 count) {
    if (count <= 0) return {};
    // Guard against a corrupt on-disk length field asking for gigabytes.
    if (count > 512LL * 1024 * 1024) count = 512LL * 1024 * 1024;
    std::vector<u8> buf((size_t)count);
    i64 n = read(offset, buf.data(), count);
    if (n <= 0) return {};
    buf.resize((size_t)n);
    return buf;
}

std::vector<u8> DiskReader::readExact(u64 offset, i64 count) {
    auto v = readBlock(offset, count);
    if ((i64)v.size() != count) return {};
    return v;
}

std::string DiskReader::readString(u64 offset, i64 count) {
    auto v = readBlock(offset, count);
    return std::string(v.begin(), v.end());
}

// ---------------------------------------------------------------------------

std::string describeOpenFailure(const std::string& path) {
    if (path.empty()) return "no image path provided";
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0) {
        if (path.rfind("/dev/", 0) == 0)
            return "device " + path + " does not exist on this system";
        return "file not found: " + path;
    }
    if (::access(path.c_str(), R_OK) != 0) {
        if (path.rfind("/dev/", 0) == 0)
            return "permission denied on " + path +
                   " — run the engine as root, or add your user to the 'disk' group";
        return "permission denied: " + path;
    }
    if (S_ISDIR(st.st_mode)) return path + " is a directory, not a disk image";
    return "could not open " + path + ": " + std::strerror(errno);
}

std::unique_ptr<DiskReader> openTarget(const std::string& path, i64 offset, i64 length,
                                       std::string* err) {
    auto d = std::make_unique<DiskReader>(path);
    if (!d->open(err)) return nullptr;
    if (d->deviceSize() <= 0) {
        if (err) *err = "device reports zero size: " + path;
        return nullptr;
    }
    if (offset > 0 || length > 0) {
        if (offset >= d->deviceSize()) {
            if (err) *err = "offset " + std::to_string(offset) + " is past the end of the device";
            return nullptr;
        }
        d->setWindow((u64)std::max<i64>(0, offset), length);
    }
    return d;
}

}  // namespace ghost
