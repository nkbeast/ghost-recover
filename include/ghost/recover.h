// GHOST//RECOVER — extraction, repair and imaging.
#pragma once

#include "ghost/fs.h"

namespace ghost {

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------
struct ExtractOptions {
    std::string output_dir;
    bool preserve_paths = true;    // rebuild the directory tree under output_dir
    bool preserve_times = true;
    bool write_manifest = true;    // CSV + JSON manifest with hashes and offsets
    bool compute_hashes = true;
    bool skip_zero_size = true;
    bool overwrite      = false;
    i64  max_file_size  = 64LL * 1024 * 1024 * 1024;
    std::vector<u64> only_ids;     // empty = every file in the result set
};

// Writes files described by `files` (extent lists) out of `disk`.
ExtractResult extractFiles(DiskReader& disk, const std::vector<RecoveredFile>& files,
                           const ExtractOptions& opt, Progress& prog);

// Convenience: scan then extract everything found.
ExtractResult recoverVolume(DiskReader& disk, const std::string& fsId,
                            const ScanOptions& sopt, const ExtractOptions& eopt,
                            Progress& prog);

// Streams one file's bytes (following its extent list) into a buffer.
std::vector<u8> readFileData(DiskReader& disk, const RecoveredFile& f, i64 maxBytes);

SaveResult saveBytes(const std::string& outputDir, const std::string& filename,
                     const std::vector<u8>& data);

// ---------------------------------------------------------------------------
// Repair
//
// Every repair is diagnostic by default. Passing apply=true opens the device
// read-write and commits the change — that is destructive, so the API requires
// it to be requested explicitly and reports exactly which bytes it wrote.
// ---------------------------------------------------------------------------
struct RepairOptions {
    bool apply  = false;
    bool backup = true;                  // save the original sectors first
    std::string backup_dir;
};

RepairResult repairExtSuperblock(DiskReader& disk, const RepairOptions& opt);
RepairResult repairFatBootSector(DiskReader& disk, const RepairOptions& opt);
RepairResult repairExfatBootRegion(DiskReader& disk, const RepairOptions& opt);
RepairResult repairNtfsBootSector(DiskReader& disk, const RepairOptions& opt);
RepairResult repairIso9660(DiskReader& disk, const RepairOptions& opt);
RepairResult repairGptTable(DiskReader& disk, const RepairOptions& opt);
RepairResult repairPartitionTable(DiskReader& disk, const PartitionScanResult& scan,
                                  const RepairOptions& opt);

// Dispatches on the detected filesystem.
RepairResult repairVolume(DiskReader& disk, const std::string& action,
                          const RepairOptions& opt);

std::vector<std::string> availableRepairs(const std::string& fsId);

// ---------------------------------------------------------------------------
// Imaging — ddrescue-style clone with a bad-sector map. Always image a failing
// drive before recovering from it.
// ---------------------------------------------------------------------------
struct ImageOptions {
    std::string output_path;
    std::string mapfile;             // resumable progress/bad-block map
    i64  block_size   = 1 << 20;
    i64  retry_passes = 2;
    bool sparse       = true;
    bool verify       = false;       // re-read and hash after writing
    i64  start        = 0;
    i64  length       = 0;           // 0 = whole device
};

struct ImageResult {
    bool ok = false;
    std::string error;
    std::string output_path;
    i64 bytes_copied  = 0;
    i64 bytes_bad     = 0;
    i64 bad_regions   = 0;
    i64 elapsed_ms    = 0;
    double rate_mb_s  = 0;
    std::string md5;
    std::vector<Extent> bad_map;
};

ImageResult createImage(DiskReader& disk, const ImageOptions& opt, Progress& prog);

}  // namespace ghost
