// GHOST RECOVER — hashing, encoding, path and string utilities.
#pragma once

#include "ghost/types.h"

namespace ghost {

// ---------------------------------------------------------------------------
// Hashing. MD5/SHA1 are needed for forensic manifests and for content-based
// deduplication (the old carver deduped on a 4 KiB FNV prefix, which collapsed
// distinct files that shared a header and let true duplicates through).
// ---------------------------------------------------------------------------
u32 crc32(const u8* data, size_t len, u32 seed = 0);
u32 crc32c(const u8* data, size_t len, u32 seed = 0);   // Castagnoli — ext4/btrfs metadata

class MD5 {
public:
    MD5();
    void update(const u8* data, size_t len);
    void update(const std::vector<u8>& v) { update(v.data(), v.size()); }
    std::string hex();
private:
    void block(const u8* p);
    u32 a_, b_, c_, d_;
    u64 len_ = 0;
    u8  buf_[64];
    size_t buflen_ = 0;
    bool done_ = false;
    u8  digest_[16];
};

class SHA1 {
public:
    SHA1();
    void update(const u8* data, size_t len);
    void update(const std::vector<u8>& v) { update(v.data(), v.size()); }
    std::string hex();
private:
    void block(const u8* p);
    u32 h_[5];
    u64 len_ = 0;
    u8  buf_[64];
    size_t buflen_ = 0;
    bool done_ = false;
    u8  digest_[20];
};

std::string md5Hex(const u8* data, size_t len);
std::string sha1Hex(const u8* data, size_t len);

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------
std::string base64Encode(const u8* data, size_t len);
std::vector<u8> base64Decode(const std::string& s);

// UTF-16LE (NTFS/exFAT/Joliet/GPT names) → UTF-8.
std::string utf16leToUtf8(const u8* data, size_t bytes);
std::string utf16beToUtf8(const u8* data, size_t bytes);

std::string toHex(const u8* data, size_t len, bool spaced = false);
std::string guidToString(const u8* g);   // mixed-endian GPT GUID

// ---------------------------------------------------------------------------
// Paths and filenames
// ---------------------------------------------------------------------------
// Strips path separators, control characters and Windows-reserved characters
// so a hostile or corrupt filename can never escape the output directory.
std::string sanitizeFilename(const std::string& name);
// Sanitizes each component of a volume-relative path and rejects "..".
std::string sanitizeRelPath(const std::string& path);

bool makeDirs(const std::string& path);
bool fileExists(const std::string& path);
i64  fileSize(const std::string& path);
std::string joinPath(const std::string& a, const std::string& b);
std::string dirName(const std::string& p);
std::string baseName(const std::string& p);
std::string extensionOf(const std::string& p);
// Returns `dir/name`, appending _1, _2 ... before the extension on collision.
std::string uniquePath(const std::string& dir, const std::string& name);
// Canonical absolute path with symlinks resolved; empty if it does not exist.
std::string realPathOf(const std::string& p);
bool pathIsWithin(const std::string& child, const std::string& parent);

std::string defaultOutputRoot();   // $GHOST_OUTPUT, else $HOME/ghost-recover-output

// When the engine is running as root because the user elevated it, anything it
// writes would otherwise end up owned by root and be undeletable by the person
// who asked for the recovery. sudo and pkexec both record who invoked them, so
// hand ownership of created files and directories back to that account.
// No-ops when not root, or when the original user cannot be determined.
void adoptOwnership(const std::string& path);
bool runningElevatedForUser(u32* uidOut, u32* gidOut);

// True when `outputPath` lives on the very device `sourcePath` is being read
// from. Writing recovered data back onto the disk it came from overwrites the
// unallocated space still holding the rest of it, which is the single most
// destructive mistake in a recovery, so callers refuse rather than warn.
bool writesBackOntoSource(const std::string& outputPath, const std::string& sourcePath);

// ---------------------------------------------------------------------------
// Strings and numbers
// ---------------------------------------------------------------------------
std::string toLower(std::string s);
std::string trim(const std::string& s);
bool startsWith(const std::string& s, const std::string& p);
bool endsWith(const std::string& s, const std::string& p);
std::string humanSize(i64 bytes);
std::string isoTime(i64 unixSeconds);

// Windows FILETIME (100 ns since 1601) → unix seconds.
i64 filetimeToUnix(u64 ft);
// FAT packed date/time → unix seconds.
i64 fatTimeToUnix(u16 date, u16 time, u8 tenths = 0);
// HFS+ epoch (1904) → unix seconds.
i64 hfsTimeToUnix(u32 t);

// Shannon entropy in bits/byte. Used to reject high-entropy noise that happens
// to contain a file signature, and to flag encrypted/compressed content.
double shannonEntropy(const u8* data, size_t len);
bool   looksLikeText(const u8* data, size_t len, double minPrintable = 0.90);

// Monotonic milliseconds since process start.
i64 nowMs();

// Physical RAM in KiB as reported by /proc/meminfo, 0 if it cannot be read.
i64 systemRamKB();
// RAM-scaled cap for in-memory scan/result lists (see util.cpp).
i64 defaultMaxFiles();
i64 defaultMaxResultBytes();

}  // namespace ghost
