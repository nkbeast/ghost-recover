// GHOST//RECOVER — physical device enumeration, partition tables, RAID.
#pragma once

#include "ghost/io.h"

namespace ghost {

// ---------------------------------------------------------------------------
// Device enumeration
// ---------------------------------------------------------------------------
std::vector<DiskInfo> detectDisks();

// ---------------------------------------------------------------------------
// Partition tables
// ---------------------------------------------------------------------------
struct PartitionOptions {
    bool detect_filesystems = true;
    bool find_deleted       = true;   // signature-scan for partitions missing from the table
    i64  deleted_scan_limit = 0;      // bytes to scan for orphaned boot sectors (0 = auto)
};

PartitionScanResult scanPartitions(DiskReader& disk, const PartitionOptions& opt,
                                   Progress& prog);
PartitionScanResult scanPartitions(DiskReader& disk);   // defaults

// Regions of the volume the filesystem considers free. Used to target carving
// at unallocated space, which is where deleted data actually lives.
std::vector<Extent> unallocatedRegions(DiskReader& disk, const std::string& fsId,
                                       Progress& prog);

// ---------------------------------------------------------------------------
// RAID
// ---------------------------------------------------------------------------
enum class RaidLevel { Unknown, Linear, Raid0, Raid1, Raid5, Raid6, Raid10 };

const char* raidLevelName(RaidLevel l);
RaidLevel   raidLevelFromString(const std::string& s);

struct RaidMember {
    std::string path;
    int   role       = -1;      // position in the array; -1 = unknown
    i64   data_offset = 0;      // where array data starts inside the member
    i64   size        = 0;
    bool  present     = true;   // false = missing/failed member, reconstruct it
    std::string uuid;
};

struct RaidLayout {
    RaidLevel level = RaidLevel::Unknown;
    i64  chunk_size = 65536;
    int  members    = 0;
    // Linux md parity layouts: "left-symmetric" (default), "left-asymmetric",
    // "right-symmetric", "right-asymmetric".
    std::string parity_layout = "left-symmetric";
    std::vector<RaidMember> disks;
    i64  data_size  = 0;        // usable bytes in the assembled array
    double confidence = 0;
    std::string detected_from;  // "mdraid-superblock" | "heuristic" | "manual"
    std::vector<std::string> notes;
    // Set when several geometries fit equally well and the data cannot settle
    // it. The chosen one is a convention, not a deduction.
    bool ambiguous = false;
    std::vector<std::string> alternatives;
};

// Reads Linux md superblocks (0.90 and 1.x) from each member.
bool probeMdSuperblock(const std::string& path, RaidMember& member, RaidLayout& layout,
                       std::string* err);

// Brute-forces chunk size / member order / parity layout by looking for a valid
// filesystem at the start of the assembled array. Used when superblocks are gone.
RaidLayout detectRaidLayout(const std::vector<std::string>& memberPaths, Progress& prog);

// A virtual device that presents the assembled array. Writes the reconstruction
// to `outPath` (sparse) so the rest of the engine can treat it as an image.
struct RaidBuildResult {
    bool ok = false;
    std::string error;
    std::string output_path;
    i64 bytes_written = 0;
    i64 stripes_reconstructed = 0;   // stripes rebuilt from parity
    i64 unrecoverable_stripes = 0;
    RaidLayout layout;
};

RaidBuildResult assembleRaid(const RaidLayout& layout, const std::string& outPath,
                             i64 maxBytes, Progress& prog);

// Reads a single logical offset out of an array without materialising it.
class RaidReader {
public:
    explicit RaidReader(const RaidLayout& layout);
    ~RaidReader();
    bool open(std::string* err);
    i64  size() const { return size_; }
    i64  read(u64 offset, u8* buf, i64 count);
    i64  degradedStripes() const { return degraded_; }
private:
    i64  readStripeUnit(int diskIdx, i64 unitOffset, u8* buf, i64 count);
    RaidLayout layout_;
    std::vector<std::unique_ptr<DiskReader>> readers_;
    i64 size_ = 0;
    i64 degraded_ = 0;
};

}  // namespace ghost
