#include "ghost/util.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

namespace ghost {

// ---------------------------------------------------------------------------
// CRC32
// ---------------------------------------------------------------------------
namespace {
struct Crc32Table {
    u32 t[256];
    explicit Crc32Table(u32 poly) {
        for (u32 i = 0; i < 256; i++) {
            u32 c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (poly ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
    }
};
const Crc32Table kIeee(0xEDB88320u);
const Crc32Table kCastagnoli(0x82F63B78u);
}  // namespace

u32 crc32(const u8* d, size_t n, u32 seed) {
    u32 c = ~seed;
    for (size_t i = 0; i < n; i++) c = kIeee.t[(c ^ d[i]) & 0xFF] ^ (c >> 8);
    return ~c;
}

u32 crc32c(const u8* d, size_t n, u32 seed) {
    u32 c = ~seed;
    for (size_t i = 0; i < n; i++) c = kCastagnoli.t[(c ^ d[i]) & 0xFF] ^ (c >> 8);
    return ~c;
}

// ---------------------------------------------------------------------------
// MD5 (RFC 1321)
// ---------------------------------------------------------------------------
namespace {
inline u32 rotl32(u32 x, int c) { return (x << c) | (x >> (32 - c)); }
const u32 kMd5K[64] = {
    0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
    0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
    0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
    0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
    0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
    0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
    0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
    0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391};
const int kMd5S[64] = {
    7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
    5, 9,14,20,5, 9,14,20,5, 9,14,20,5, 9,14,20,
    4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
    6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21};
}  // namespace

MD5::MD5() : a_(0x67452301), b_(0xefcdab89), c_(0x98badcfe), d_(0x10325476) {
    std::memset(buf_, 0, sizeof(buf_));
    std::memset(digest_, 0, sizeof(digest_));
}

void MD5::block(const u8* p) {
    u32 m[16];
    for (int i = 0; i < 16; i++)
        m[i] = (u32)p[i*4] | (u32)p[i*4+1] << 8 | (u32)p[i*4+2] << 16 | (u32)p[i*4+3] << 24;
    u32 A = a_, B = b_, C = c_, D = d_;
    for (int i = 0; i < 64; i++) {
        u32 f; int g;
        if (i < 16)      { f = (B & C) | (~B & D);        g = i; }
        else if (i < 32) { f = (D & B) | (~D & C);        g = (5*i + 1) & 15; }
        else if (i < 48) { f = B ^ C ^ D;                 g = (3*i + 5) & 15; }
        else             { f = C ^ (B | ~D);              g = (7*i) & 15; }
        u32 tmp = D; D = C; C = B;
        B = B + rotl32(A + f + kMd5K[i] + m[g], kMd5S[i]);
        A = tmp;
    }
    a_ += A; b_ += B; c_ += C; d_ += D;
}

void MD5::update(const u8* data, size_t len) {
    if (done_) return;
    len_ += len;
    while (len) {
        size_t take = std::min(len, size_t(64) - buflen_);
        std::memcpy(buf_ + buflen_, data, take);
        buflen_ += take; data += take; len -= take;
        if (buflen_ == 64) { block(buf_); buflen_ = 0; }
    }
}

std::string MD5::hex() {
    if (!done_) {
        u64 bits = len_ * 8;
        u8 pad = 0x80;
        update(&pad, 1);
        u8 zero = 0;
        while (buflen_ != 56) update(&zero, 1);
        u8 lenb[8];
        for (int i = 0; i < 8; i++) lenb[i] = (u8)(bits >> (8 * i));
        // Bypass update() so the length bytes do not extend len_.
        std::memcpy(buf_ + buflen_, lenb, 8);
        block(buf_);
        u32 w[4] = {a_, b_, c_, d_};
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++) digest_[i*4+j] = (u8)(w[i] >> (8 * j));
        done_ = true;
    }
    return toHex(digest_, 16);
}

// ---------------------------------------------------------------------------
// SHA-1 (RFC 3174)
// ---------------------------------------------------------------------------
SHA1::SHA1() {
    h_[0] = 0x67452301; h_[1] = 0xEFCDAB89; h_[2] = 0x98BADCFE;
    h_[3] = 0x10325476; h_[4] = 0xC3D2E1F0;
    std::memset(buf_, 0, sizeof(buf_));
    std::memset(digest_, 0, sizeof(digest_));
}

void SHA1::block(const u8* p) {
    u32 w[80];
    for (int i = 0; i < 16; i++)
        w[i] = (u32)p[i*4] << 24 | (u32)p[i*4+1] << 16 | (u32)p[i*4+2] << 8 | (u32)p[i*4+3];
    for (int i = 16; i < 80; i++)
        w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    u32 a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4];
    for (int i = 0; i < 80; i++) {
        u32 f, k;
        if (i < 20)      { f = (b & c) | (~b & d);          k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;                   k = 0xCA62C1D6; }
        u32 t = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = t;
    }
    h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e;
}

void SHA1::update(const u8* data, size_t len) {
    if (done_) return;
    len_ += len;
    while (len) {
        size_t take = std::min(len, size_t(64) - buflen_);
        std::memcpy(buf_ + buflen_, data, take);
        buflen_ += take; data += take; len -= take;
        if (buflen_ == 64) { block(buf_); buflen_ = 0; }
    }
}

std::string SHA1::hex() {
    if (!done_) {
        u64 bits = len_ * 8;
        u8 pad = 0x80;
        update(&pad, 1);
        u8 zero = 0;
        while (buflen_ != 56) update(&zero, 1);
        u8 lenb[8];
        for (int i = 0; i < 8; i++) lenb[i] = (u8)(bits >> (56 - 8 * i));
        std::memcpy(buf_ + buflen_, lenb, 8);
        block(buf_);
        for (int i = 0; i < 5; i++)
            for (int j = 0; j < 4; j++) digest_[i*4+j] = (u8)(h_[i] >> (24 - 8 * j));
        done_ = true;
    }
    return toHex(digest_, 20);
}

std::string md5Hex(const u8* d, size_t n)  { MD5 h;  h.update(d, n); return h.hex(); }
std::string sha1Hex(const u8* d, size_t n) { SHA1 h; h.update(d, n); return h.hex(); }

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------
static const char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const u8* d, size_t n) {
    std::string o;
    o.reserve(((n + 2) / 3) * 4);
    for (size_t i = 0; i < n; i += 3) {
        u32 v = (u32)d[i] << 16;
        if (i + 1 < n) v |= (u32)d[i+1] << 8;
        if (i + 2 < n) v |= (u32)d[i+2];
        o += kB64[(v >> 18) & 63];
        o += kB64[(v >> 12) & 63];
        o += (i + 1 < n) ? kB64[(v >> 6) & 63] : '=';
        o += (i + 2 < n) ? kB64[v & 63] : '=';
    }
    return o;
}

std::vector<u8> base64Decode(const std::string& s) {
    static i8 tbl[256];
    static bool init = false;
    if (!init) {
        std::memset(tbl, -1, sizeof(tbl));
        for (int i = 0; i < 64; i++) tbl[(u8)kB64[i]] = (i8)i;
        init = true;
    }
    std::vector<u8> out;
    out.reserve(s.size() * 3 / 4 + 3);
    u32 val = 0;
    int bits = 0;
    for (char ch : s) {
        if (ch == '=') break;
        i8 d = tbl[(u8)ch];
        if (d < 0) continue;
        val = (val << 6) | (u32)d;
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back((u8)((val >> bits) & 0xFF)); }
    }
    return out;
}

static void appendUtf8(std::string& out, u32 cp) {
    if (cp < 0x80) out += (char)cp;
    else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
    else if (cp < 0x10000) {
        out += (char)(0xE0 | (cp >> 12));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    } else {
        out += (char)(0xF0 | (cp >> 18));
        out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    }
}

static std::string utf16ToUtf8(const u8* d, size_t bytes, bool big) {
    std::string out;
    out.reserve(bytes);
    for (size_t i = 0; i + 1 < bytes; i += 2) {
        u32 c = big ? ((u32)d[i] << 8 | d[i+1]) : ((u32)d[i+1] << 8 | d[i]);
        if (c == 0) break;
        if (c >= 0xD800 && c <= 0xDBFF && i + 3 < bytes) {
            u32 lo = big ? ((u32)d[i+2] << 8 | d[i+3]) : ((u32)d[i+3] << 8 | d[i+2]);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                i += 2;
            }
        }
        appendUtf8(out, c);
    }
    return out;
}

std::string utf16leToUtf8(const u8* d, size_t bytes) { return utf16ToUtf8(d, bytes, false); }
std::string utf16beToUtf8(const u8* d, size_t bytes) { return utf16ToUtf8(d, bytes, true); }

std::string toHex(const u8* d, size_t n, bool spaced) {
    static const char* H = "0123456789abcdef";
    std::string o;
    o.reserve(n * (spaced ? 3 : 2));
    for (size_t i = 0; i < n; i++) {
        o += H[d[i] >> 4];
        o += H[d[i] & 15];
        if (spaced && i + 1 < n) o += ' ';
    }
    return o;
}

std::string guidToString(const u8* g) {
    char buf[40];
    snprintf(buf, sizeof(buf),
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
             g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
    return buf;
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------
std::string sanitizeFilename(const std::string& name) {
    std::string o;
    o.reserve(name.size());
    for (unsigned char c : name) {
        if (c < 0x20 || c == 0x7F) continue;
        switch (c) {
            case '/': case '\\': case ':': case '*': case '?':
            case '"': case '<':  case '>': case '|':
                o += '_';
                break;
            default: o += (char)c;
        }
    }
    // A leading dot would hide the file; a name of only dots escapes upward.
    size_t firstGood = o.find_first_not_of(". ");
    if (firstGood == std::string::npos) o.clear();
    while (!o.empty() && (o.back() == ' ' || o.back() == '.')) o.pop_back();
    if (o.empty()) o = "unnamed";
    if (o.size() > 200) o.resize(200);
    return o;
}

std::string sanitizeRelPath(const std::string& path) {
    std::string out;
    size_t i = 0;
    while (i < path.size()) {
        size_t j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        std::string comp = path.substr(i, j - i);
        i = j + 1;
        if (comp.empty() || comp == "." || comp == "..") continue;
        std::string clean = sanitizeFilename(comp);
        if (clean.empty()) continue;
        if (!out.empty()) out += '/';
        out += clean;
    }
    return out;
}

bool makeDirs(const std::string& path) {
    if (path.empty()) return false;
    std::string cur;
    if (path[0] == '/') cur = "/";
    size_t i = 0;
    while (i < path.size()) {
        size_t j = path.find('/', i);
        if (j == std::string::npos) j = path.size();
        std::string comp = path.substr(i, j - i);
        i = j + 1;
        if (comp.empty()) continue;
        if (cur.empty()) cur = comp;
        else if (cur == "/") cur += comp;
        else cur += "/" + comp;
        if (::mkdir(cur.c_str(), 0755) != 0) {
            if (errno != EEXIST) {
                struct stat st{};
                if (::stat(cur.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return false;
            }
        } else {
            adoptOwnership(cur);
        }
    }
    return true;
}

bool fileExists(const std::string& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0;
}

i64 fileSize(const std::string& p) {
    struct stat st{};
    if (::stat(p.c_str(), &st) != 0) return -1;
    return (i64)st.st_size;
}

std::string joinPath(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    if (b.empty()) return a;
    if (a.back() == '/') return a + b;
    return a + "/" + b;
}

std::string dirName(const std::string& p) {
    size_t s = p.find_last_of('/');
    if (s == std::string::npos) return ".";
    if (s == 0) return "/";
    return p.substr(0, s);
}

std::string baseName(const std::string& p) {
    size_t s = p.find_last_of('/');
    return (s == std::string::npos) ? p : p.substr(s + 1);
}

std::string extensionOf(const std::string& p) {
    std::string b = baseName(p);
    size_t d = b.find_last_of('.');
    if (d == std::string::npos || d == 0 || d + 1 >= b.size()) return {};
    return toLower(b.substr(d + 1));
}

std::string uniquePath(const std::string& dir, const std::string& name) {
    std::string clean = sanitizeFilename(name);
    std::string cand  = joinPath(dir, clean);
    if (!fileExists(cand)) return cand;
    size_t dot = clean.find_last_of('.');
    std::string stem = (dot == std::string::npos || dot == 0) ? clean : clean.substr(0, dot);
    std::string ext  = (dot == std::string::npos || dot == 0) ? ""    : clean.substr(dot);
    for (int i = 1; i < 100000; i++) {
        std::string c = joinPath(dir, stem + "_" + std::to_string(i) + ext);
        if (!fileExists(c)) return c;
    }
    return cand;
}

std::string realPathOf(const std::string& p) {
    char buf[PATH_MAX];
    if (::realpath(p.c_str(), buf)) return buf;
    return {};
}

bool pathIsWithin(const std::string& child, const std::string& parent) {
    if (parent.empty()) return false;
    std::string c = realPathOf(child);
    std::string par = realPathOf(parent);
    if (par.empty()) return false;
    if (c.empty()) {
        // Target may not exist yet — resolve its directory instead.
        std::string d = realPathOf(dirName(child));
        if (d.empty()) return false;
        c = joinPath(d, baseName(child));
    }
    if (par.back() != '/') par += '/';
    return c.rfind(par, 0) == 0 || c + "/" == par;
}

bool runningElevatedForUser(u32* uidOut, u32* gidOut) {
    if (::geteuid() != 0) return false;
    const char* uidStr = ::getenv("PKEXEC_UID");
    const char* gidStr = nullptr;
    if (!uidStr) {
        uidStr = ::getenv("SUDO_UID");
        gidStr = ::getenv("SUDO_GID");
    }
    if (!uidStr || !*uidStr) return false;
    u32 uid = 0, gid = 0;
    try { uid = (u32)std::stoul(uidStr); } catch (...) { return false; }
    if (uid == 0) return false;
    if (gidStr && *gidStr) { try { gid = (u32)std::stoul(gidStr); } catch (...) { gid = uid; } }
    else gid = uid;
    if (uidOut) *uidOut = uid;
    if (gidOut) *gidOut = gid;
    return true;
}

void adoptOwnership(const std::string& path) {
    u32 uid = 0, gid = 0;
    if (path.empty() || !runningElevatedForUser(&uid, &gid)) return;
    // Best effort: a failure here is not worth failing a recovery over.
    (void)::lchown(path.c_str(), (uid_t)uid, (gid_t)gid);
}

bool writesBackOntoSource(const std::string& outputPath, const std::string& sourcePath) {
    if (outputPath.empty() || sourcePath.empty()) return false;
    struct stat src{};
    if (::stat(sourcePath.c_str(), &src) != 0) return false;

    // Find the nearest existing ancestor of the output path.
    std::string probe = outputPath;
    struct stat out{};
    while (!probe.empty() && ::stat(probe.c_str(), &out) != 0) {
        std::string parent = dirName(probe);
        if (parent == probe) return false;
        probe = parent;
    }
    if (probe.empty()) return false;

    if (S_ISBLK(src.st_mode)) {
        // Recovering from a block device: refuse if the destination filesystem
        // is mounted from that same device, or from any partition of the same
        // physical disk — imaging /dev/sdb must not write to a partition of
        // /dev/sdb that happens to be mounted at the output location.
        if (out.st_dev == src.st_rdev) return true;

        // Find the device name in /proc/partitions, then its whole-disk name
        // via sysfs: a partition node lives at /sys/block/<disk>/<part> and
        // carries a "partition" attribute.
        std::string srcName;
        {
            std::ifstream parts("/proc/partitions");
            std::string line;
            while (std::getline(parts, line)) {
                unsigned maj, min;
                unsigned long long blk;
                std::string name;
                std::istringstream iss(line);
                if (iss >> maj >> min >> blk >> name && ::makedev(maj, min) == src.st_rdev) {
                    srcName = name;
                    break;
                }
            }
        }
        if (srcName.empty()) return false;

        std::string whole;
        DIR* dir = ::opendir("/sys/block");
        if (dir) {
            struct dirent* e;
            while ((e = ::readdir(dir)) != nullptr) {
                std::string w = e->d_name;
                if (w == "." || w == "..") continue;
                if (w == srcName) { whole = w; break; }                       // whole disk itself
                if (fileExists("/sys/block/" + w + "/" + srcName + "/partition")) {
                    whole = w;                                                // a partition of w
                    break;
                }
            }
            ::closedir(dir);
        }
        if (whole.empty()) return false;

        std::ifstream parts("/proc/partitions");
        std::string line;
        while (std::getline(parts, line)) {
            unsigned maj, min;
            unsigned long long blk;
            std::string name;
            std::istringstream iss(line);
            if (!(iss >> maj >> min >> blk >> name)) continue;
            bool onSourceDisk = (name == whole) || (name.size() > whole.size() &&
                                 name.compare(0, whole.size(), whole) == 0 &&
                                 fileExists("/sys/block/" + whole + "/" + name + "/partition"));
            if (onSourceDisk && ::makedev(maj, min) == (dev_t)out.st_dev) return true;
        }
        return false;
    }
    // Recovering from an image file: refuse only if the destination is that
    // file itself or sits underneath it.
    std::string realSrc = realPathOf(sourcePath);
    std::string realOut = realPathOf(probe);
    if (!realSrc.empty() && realOut == realSrc) return true;
    return false;
}

std::string defaultOutputRoot() {
    if (const char* env = ::getenv("GHOST_OUTPUT"); env && *env) return env;
    if (const char* home = ::getenv("HOME"); home && *home)
        return joinPath(home, "ghost-recover-output");
    return "/var/tmp/ghost-recover-output";
}

// ---------------------------------------------------------------------------
// Strings, numbers, time
// ---------------------------------------------------------------------------
std::string toLower(std::string s) {
    for (auto& c : s) c = (char)::tolower((unsigned char)c);
    return s;
}

std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

bool startsWith(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }
bool endsWith(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

std::string humanSize(i64 b) {
    char buf[48];
    double v = (double)b;
    if (b < 1024) snprintf(buf, sizeof(buf), "%lld B", (long long)b);
    else if (b < 1024LL * 1024) snprintf(buf, sizeof(buf), "%.1f KB", v / 1024);
    else if (b < 1024LL * 1024 * 1024) snprintf(buf, sizeof(buf), "%.2f MB", v / (1024 * 1024));
    else if (b < 1024LL * 1024 * 1024 * 1024) snprintf(buf, sizeof(buf), "%.2f GB", v / (1024.0 * 1024 * 1024));
    else snprintf(buf, sizeof(buf), "%.2f TB", v / (1024.0 * 1024 * 1024 * 1024));
    return buf;
}

std::string isoTime(i64 t) {
    if (t <= 0) return {};
    time_t tt = (time_t)t;
    struct tm tmv{};
    if (!gmtime_r(&tt, &tmv)) return {};
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
    return buf;
}

i64 filetimeToUnix(u64 ft) {
    if (ft == 0) return 0;
    // 116444736000000000 = 100 ns intervals between 1601-01-01 and 1970-01-01
    if (ft < 116444736000000000ULL) return 0;
    return (i64)((ft - 116444736000000000ULL) / 10000000ULL);
}

i64 fatTimeToUnix(u16 date, u16 time, u8 tenths) {
    if (date == 0) return 0;
    struct tm tmv{};
    tmv.tm_year = ((date >> 9) & 0x7F) + 80;   // 1980 base
    tmv.tm_mon  = (int)((date >> 5) & 0x0F) - 1;
    tmv.tm_mday = date & 0x1F;
    tmv.tm_hour = (time >> 11) & 0x1F;
    tmv.tm_min  = (time >> 5) & 0x3F;
    tmv.tm_sec  = (int)(time & 0x1F) * 2 + (tenths >= 100 ? 1 : 0);
    if (tmv.tm_mon < 0 || tmv.tm_mon > 11 || tmv.tm_mday < 1 || tmv.tm_mday > 31) return 0;
    time_t t = timegm(&tmv);
    return t == (time_t)-1 ? 0 : (i64)t;
}

i64 hfsTimeToUnix(u32 t) {
    if (t == 0) return 0;
    const u32 kOffset = 2082844800u;   // 1904-01-01 → 1970-01-01
    return (t > kOffset) ? (i64)(t - kOffset) : 0;
}

double shannonEntropy(const u8* d, size_t n) {
    if (n == 0) return 0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < n; i++) counts[d[i]]++;
    double h = 0;
    for (int i = 0; i < 256; i++) {
        if (!counts[i]) continue;
        double p = (double)counts[i] / (double)n;
        h -= p * std::log2(p);
    }
    return h;
}

bool looksLikeText(const u8* d, size_t n, double minPrintable) {
    if (n == 0) return false;
    size_t good = 0;
    for (size_t i = 0; i < n; i++) {
        u8 c = d[i];
        if ((c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r' || c >= 0x80) good++;
        if (c == 0) return false;
    }
    return (double)good / (double)n >= minPrintable;
}

i64 nowMs() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

i64 systemRamKB() {
    std::ifstream f("/proc/meminfo");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("MemTotal:", 0) != 0) continue;
        std::istringstream in(line);
        std::string key;
        i64 kb = 0;
        if (in >> key >> kb) return kb;
    }
    return 0;
}

// Bound in-memory job results so a scan can never silently eat the whole box:
// each recovered file costs roughly 1.2 KiB resident (name/path strings, extent
// list, flags), so the default caps a result at ~RAM/4. On 1 GiB that is ~200k
// files, on 16 GiB ~3.3 M. A box with unknown RAM keeps the previous 500k.
i64 defaultMaxFiles() {
    const i64 kb = systemRamKB();
    if (kb <= 0) return 500000;
    i64 n = kb * 1024 / 4 / 1280;
    return std::clamp<i64>(n, 50000, 5000000);
}

}  // namespace ghost
