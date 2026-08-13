// GHOST RECOVER — filesystem drivers.
#pragma once

#include "ghost/io.h"

namespace ghost {

struct ScanOptions {
    bool deep            = true;    // walk every allocation group / whole MFT
    bool journal         = true;    // mine the journal / log for deleted metadata
    bool slack           = true;    // carve directory slack space for lost entries
    bool orphans         = true;    // scan for inodes/records not reachable from any directory
    bool include_live    = true;    // report allocated files as well as deleted ones
    bool resolve_paths   = true;    // reconstruct full paths (needs a directory pass)
    i64  max_files       = 500000;  // hard cap so a corrupt volume cannot exhaust memory
    i64  max_scan_bytes  = 0;       // 0 = whole volume
    i64  max_result_bytes = -1;     // byte budget for res.files; -1 = set from RAM in scanVolume
};

// Every driver has this shape. `progress` is updated as the scan runs and is
// polled by the job manager; drivers must check progress.cancelled() in their
// long loops.
using FsScanFn = ScanResult (*)(DiskReader&, const ScanOptions&, Progress&);

struct FsDriver {
    const char* id;
    const char* name;
    const char* family;
    FsScanFn    scan;
};

const FsDriver*        findDriver(const std::string& fsId);
std::vector<FsDriver>  allDrivers();

// Detect, then dispatch. `fsId` empty means auto-detect.
ScanResult scanVolume(DiskReader& disk, const std::string& fsId,
                      const ScanOptions& opt, Progress& prog);

DetectResult detectFilesystem(DiskReader& disk);
std::vector<FsEntry> filesystemRegistry();

// ---------------------------------------------------------------------------
// Driver entry points
// ---------------------------------------------------------------------------
namespace ext      { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace ntfs     { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace fat      { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace exfat    { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace xfs      { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace btrfs    { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace f2fs     { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace hfs      { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace apfs     { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace iso9660  { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace udf      { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace squashfs { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace cramfs   { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace romfs    { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace minixfs  { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace jffs2    { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace ufs      { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace reiserfs { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace jfs      { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }
namespace zfs      { ScanResult scan(DiskReader&, const ScanOptions&, Progress&); }

// ---------------------------------------------------------------------------
// Helpers shared by drivers
// ---------------------------------------------------------------------------

// Clamps `f.extents` to the volume, drops runs that fall outside it and fills
// in `recoverable`. Every driver calls this before appending a file so a
// corrupt length field can never produce a multi-terabyte read later.
void finalizeFile(RecoveredFile& f, i64 volumeSize);

// True when the extent list is plausible for a file of `size` bytes on a
// volume of `volumeSize` bytes.
bool extentsPlausible(const std::vector<Extent>& ex, i64 size, i64 volumeSize);

// Appends `f` to `res`, accounting its resident cost against
// `opt.max_result_bytes`. Returns false when the budget is exhausted and the
// driver should stop scanning (it sets `res.truncated`).
inline bool pushFile(ScanResult& res, RecoveredFile&& f, const ScanOptions& opt) {
    res.files.push_back(std::move(f));
    const auto& b = res.files.back();
    // 512 flat (fixed fields, string SSO, vector capacity slack) + strings +
    // 32B per extent + resident data. Deliberately pessimistic so the scan
    // stops before the RSS curve surprises anyone.
    res.resultBytes += 512 + (i64)b.name.size() + (i64)b.path.size() +
                       (i64)b.method.size() +
                       32 * (i64)b.extents.size() +
                       8 * (i64)b.decomp_sizes.size() +
                       (i64)b.resident.size();
    if (opt.max_result_bytes > 0 && res.resultBytes > opt.max_result_bytes) {
        res.truncated = true;
        return false;
    }
    return (i64)res.files.size() < opt.max_files;
}

}  // namespace ghost
