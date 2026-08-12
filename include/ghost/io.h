// GHOST//RECOVER — device / image I/O.
#pragma once

#include "ghost/types.h"

namespace ghost {

// ---------------------------------------------------------------------------
// DiskReader
//
// Reads a raw block device or an image file through a *window* (base offset +
// length) so a partition can be addressed with volume-relative offsets while
// still living inside a whole-disk image. Every read is clamped to the window;
// a driver can no longer walk off the end of its partition into the next one.
//
// Features that the previous implementation lacked and that recovery work
// genuinely needs:
//   * a block cache — filesystem drivers issue millions of small reads into
//     inode tables and B-trees; uncached pread() per field made deep scans
//     take hours
//   * bad-sector tolerance — a failing pread() no longer aborts the read.
//     The reader retries sector-by-sector, zero-fills what it cannot get and
//     records the bad range, which is exactly what a recovery tool must do on
//     a dying drive
//   * clone() — worker threads each get their own file descriptor and cache
//     instead of contending on one
// ---------------------------------------------------------------------------
class DiskReader {
public:
    explicit DiskReader(std::string path);
    ~DiskReader();

    DiskReader(const DiskReader&) = delete;
    DiskReader& operator=(const DiskReader&) = delete;

    bool open(std::string* err = nullptr);
    void close();
    bool isOpen() const { return fd_ >= 0; }

    // A second independent reader on the same path, inheriting the window.
    std::unique_ptr<DiskReader> clone() const;

    const std::string& path() const { return path_; }

    // ---- window -----------------------------------------------------------
    // All public offsets are relative to `base`. size() reports the window
    // length, never the underlying device length.
    void setWindow(u64 base, i64 length);
    void resetWindow();
    u64  base() const { return base_; }
    i64  size() const { return size_; }
    i64  deviceSize() const { return device_size_; }

    bool isRawDevice() const { return is_raw_; }
    i64  sectorSize() const { return sector_size_; }

    // ---- reads ------------------------------------------------------------
    // Returns the number of bytes placed in `buf`. Short reads mean the window
    // ended; unreadable sectors inside the window are zero-filled and counted.
    i64 read(u64 offset, void* buf, i64 count);

    std::vector<u8> readBlock(u64 offset, i64 count);
    std::string     readString(u64 offset, i64 count);

    // Read exactly `count` bytes or return an empty vector. Use when a short
    // read must be treated as a parse failure rather than as truncation.
    std::vector<u8> readExact(u64 offset, i64 count);

    template <typename T> T readLE(u64 offset) {
        u8 raw[sizeof(T)] = {0};
        read(offset, raw, (i64)sizeof(T));
        T v{};
        for (int i = (int)sizeof(T) - 1; i >= 0; i--)
            v = (T)((u64)v << 8 | raw[i]);
        return v;
    }

    // ---- health -----------------------------------------------------------
    i64  badSectorCount() const { return bad_sectors_; }
    i64  bytesRead() const { return bytes_read_; }
    const std::vector<Extent>& badRegions() const { return bad_regions_; }
    void clearHealth();

    // Cache tuning. `bytes` is a hint; rounded to whole cache blocks.
    void setCacheSize(i64 bytes);
    i64  cacheSize() const { return cache_bytes_; }
    void dropCache();

private:
    i64  rawPread(u64 abs_off, u8* dst, i64 count);
    i64  degradedPread(u64 abs_off, u8* dst, i64 count);
    void noteBad(u64 abs_off, i64 len);

    struct CacheLine {
        u64 tag   = ~0ull;   // block index, ~0 = empty
        i64 valid = 0;       // bytes actually present in `data`
        std::vector<u8> data;
    };

    std::string path_;
    int  fd_          = -1;
    bool is_raw_      = false;
    i64  device_size_ = 0;
    i64  sector_size_ = 512;

    u64 base_ = 0;
    i64 size_ = 0;

    std::vector<CacheLine> cache_;
    size_t cache_mask_ = 0;
    i64    cache_bytes_ = 0;

    i64 bad_sectors_ = 0;
    i64 bytes_read_  = 0;
    std::vector<Extent> bad_regions_;
};

// Opens `path`, applies an optional window, and returns nullptr with `err`
// populated on failure. Centralises the "why couldn't I open this" message
// that every API endpoint needs.
std::unique_ptr<DiskReader> openTarget(const std::string& path,
                                       i64 offset,
                                       i64 length,
                                       std::string* err);

// Human-readable explanation for a failed open (missing node, permissions,
// not a block device, ...).
std::string describeOpenFailure(const std::string& path);

}  // namespace ghost
