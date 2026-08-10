// GHOST//RECOVER — filesystem drivers.
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

}  // namespace ghost
