// GHOST//RECOVER — signature carving.
#pragma once

#include "ghost/io.h"

namespace ghost {

// How a carver determines where the file ends.
enum class SizeMode : u8 {
    Footer,        // scan forward for a terminator byte string
    Header,        // the header contains the length (BMP, PNG-chunks, RIFF, ...)
    Container,     // walk the container's structure (MP4 atoms, EBML, OGG pages)
    FrameStream,   // walk a stream of frames (MP3, AAC, AC3, TS, AMR)
    Text,          // run of printable bytes
    Fixed,         // constant size
    Heuristic,     // no reliable end marker — read up to max_size, trimmed
};

struct CarveSpec;
class  ByteSource;

// A validator inspects the start of a candidate and returns:
//   >0  exact size in bytes
//    0  structurally valid but size unknown (caller falls back)
//   -1  reject the candidate
using SizeFn = i64 (*)(ByteSource&, i64 offset, i64 maxSize, const CarveSpec& spec);

struct CarveSpec {
    std::string name;             // "JPEG"
    std::string ext;              // "jpg"
    std::string category;         // "image" | "video" | "audio" | "document" | "archive" |
                                  // "database" | "email" | "crypto" | "executable" |
                                  // "forensic" | "vm" | "code" | "text" | "font" | "misc"
    std::vector<u8> magic;        // primary signature
    int  magic_offset = 0;        // where `magic` sits relative to the file start
    i64  min_size = 32;
    i64  max_size = 64LL * 1024 * 1024;

    SizeMode        mode = SizeMode::Heuristic;
    std::vector<u8> footer;       // for SizeMode::Footer
    int             footer_extra = 0;   // bytes to keep after the footer match

    // Disambiguation: a second byte string that must be present, either at an
    // exact offset (confirm_offset >= 0) or anywhere within confirm_window.
    std::vector<u8> confirm;
    int             confirm_offset = -1;
    int             confirm_window = 4096;

    SizeFn validator = nullptr;   // structural walker, when the format has one
    // True when the validator walks the file's internal chain from start to
    // end (PNG chunk list, ZIP central directory, MP4 atom tree, frame
    // streams...). Such a result proves every byte in between is intact, which
    // header-only checks like BMP's size field or an ELF section table do not.
    bool whole_file = false;
    double min_entropy = -1.0;    // reject below this (unset = no check)
    double max_entropy = -1.0;    // reject above this (rejects random noise)
    int    priority = 0;          // higher wins when two specs match at one offset
};

// Reads that a validator performs. Backed by the DiskReader but with its own
// small window so validators cannot run away across the device.
class ByteSource {
public:
    ByteSource(DiskReader& d, i64 limit) : d_(d), limit_(limit) {}
    std::vector<u8> read(i64 off, i64 len);
    u8  byte(i64 off);
    u32 be32(i64 off);
    u32 le32(i64 off);
    u16 be16(i64 off);
    u16 le16(i64 off);
    i64 limit() const { return limit_; }
private:
    DiskReader& d_;
    i64 limit_;
};

const std::vector<CarveSpec>& carverRegistry();
std::vector<std::string>      carverCategories();

struct CarveOptions {
    std::string output_dir;
    i64  max_files      = 20000;
    i64  min_file_size  = 32;
    i64  max_file_size  = 4LL * 1024 * 1024 * 1024;
    bool write_files    = true;
    bool compute_hashes = true;
    bool validate       = true;      // run format validators
    bool dedup          = true;      // drop byte-identical results
    bool text_carving   = false;     // recover loose printable-text runs
    bool skip_allocated = false;     // only look at space the filesystem calls free
    int  threads        = 0;         // 0 = auto
    i64  start_offset   = 0;
    i64  length         = 0;         // 0 = to end of window
    std::vector<std::string> categories;   // empty = all
    std::vector<std::string> extensions;   // empty = all
    std::vector<Extent>      regions;      // explicit regions (unallocated map)
};

CarveResult carveDevice(DiskReader& disk, const CarveOptions& opt, Progress& prog);

// ---------------------------------------------------------------------------
// Aho-Corasick multi-pattern matcher.
//
// The old carver ran std::search once per signature per chunk — roughly 180
// full passes over every byte of the device. This walks each byte once and
// reports every signature that ends at it.
// ---------------------------------------------------------------------------
class MultiMatcher {
public:
    void add(const std::vector<u8>& pattern, int id);
    // Determinises the trie into a flat 256-way transition table so matching
    // costs one array lookup per byte regardless of how many signatures are
    // loaded.
    void build();

    // Feeds `len` bytes starting at absolute position `base`. `state` is the
    // caller's automaton state and must persist across consecutive chunks;
    // each worker thread keeps its own so the shared table stays read-only.
    // `cb(startOffset, patternId)` fires for every match.
    void scan(const u8* data, size_t len, i64 base, int& state,
              const std::function<void(i64, int)>& cb) const;

    int    initialState() const { return 0; }
    size_t patternCount() const { return patterns_; }
    size_t maxPatternLen() const { return max_len_; }
    size_t stateCount() const { return goto_.size() / 256; }

private:
    // Trie edges during construction; replaced by `goto_` after build().
    std::vector<std::map<u8, int>> edges_{1};
    std::vector<int> goto_;          // stateCount * 256 flat transition table
    std::vector<int> fail_;
    // Every pattern id that terminates at this state. Several formats share a
    // signature (RIFF is WAV, AVI, WEBP and CDR; ftyp is a dozen containers),
    // so a state has to be able to report all of them.
    std::vector<std::vector<int>> out_;
    std::vector<int> out_link_;      // next state in the suffix output chain
    std::vector<int> pat_len_;
    size_t patterns_ = 0, max_len_ = 0;
    bool   built_ = false;
};

}  // namespace ghost
