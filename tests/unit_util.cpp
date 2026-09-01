#include "ghost/types.h"
#include "ghost/util.h"

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <unistd.h>

using namespace ghost;

namespace {

int failures = 0;

void check(bool ok, const std::string& message) {
    if (ok) return;
    std::cerr << "FAIL: " << message << "\n";
    failures++;
}

std::string makeTempDir() {
    std::string tmpl = "/tmp/ghost-unit-XXXXXX";
    std::vector<char> path(tmpl.begin(), tmpl.end());
    path.push_back('\0');
    char* created = ::mkdtemp(path.data());
    return created ? std::string(created) : std::string();
}

void testBytesAccessors() {
    const u8 raw[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    Bytes b(raw, sizeof(raw));

    check(b.le16(0) == 0x2301, "le16 reads little-endian values");
    check(b.be16(0) == 0x0123, "be16 reads big-endian values");
    check(b.le32(0) == 0x67452301, "le32 reads little-endian values");
    check(b.be32(0) == 0x01234567, "be32 reads big-endian values");
    check(b.le64(0) == 0xefcdab8967452301ULL, "le64 reads little-endian values");
    check(b.be64(0) == 0x0123456789abcdefULL, "be64 reads big-endian values");

    check(!b.has((size_t)-2, 8), "has rejects overflowing ranges");
    check(b.le32(6) == 0, "integer reads outside the buffer return zero");
    check(b.str(7, 8).empty(), "string reads outside the buffer return empty");

    const u8 signedRaw[] = {0x80, 0x34, 0x12, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    Bytes signedBytes(signedRaw, sizeof(signedRaw));
    check(signedBytes.sle(0, 1) == -128, "sle sign-extends 8-bit negatives");
    check(signedBytes.sle(1, 3) == 0x1234, "sle preserves positive 24-bit values");
    check(signedBytes.sle(3, 4) == -256, "sle sign-extends 32-bit negatives");
    const u8 fullSignedRaw[] = {0x80, 0, 0, 0, 0, 0, 0, 0x80};
    Bytes fullSignedBytes(fullSignedRaw, sizeof(fullSignedRaw));
    check(fullSignedBytes.sle(0, 8) == (i64)0x8000000000000080ULL,
          "sle handles full-width values without signed shifts");
}

void testEncodingAndHashes() {
    const std::string text = "ghost";
    const auto* data = reinterpret_cast<const u8*>(text.data());

    check(base64Encode(data, text.size()) == "Z2hvc3Q=", "base64 encodes bytes");
    check(base64Decode("Z2 hv\nc3Q=") == std::vector<u8>({'g', 'h', 'o', 's', 't'}),
          "base64 decoder ignores whitespace and non-alphabet bytes");
    check(md5Hex(data, text.size()) == "71144850f4fb4cc55fc0ee6935badddf",
          "md5Hex matches a known digest");
    check(sha1Hex(data, text.size()) == "c4745785181de931cfd5bd79294cb1687d82aea9",
          "sha1Hex matches a known digest");
}

void testSanitizers() {
    check(sanitizeFilename("../bad:name?.txt") == ".._bad_name_.txt",
          "sanitizeFilename replaces path and shell-sensitive characters");
    check(sanitizeFilename("...") == "unnamed", "sanitizeFilename rejects dot-only names");
    check(sanitizeFilename("report.txt...") == "report.txt",
          "sanitizeFilename strips trailing dots");

    check(sanitizeRelPath("/safe/../evil/./name:?.txt") == "safe/evil/name__.txt",
          "sanitizeRelPath removes traversal components and cleans each name");
    check(sanitizeRelPath("../../..").empty(), "sanitizeRelPath drops pure traversal");
}

void testPathContainment() {
    const std::string root = makeTempDir();
    check(!root.empty(), "mkdtemp creates a scratch directory");
    if (root.empty()) return;

    const std::string childDir = joinPath(root, "child");
    check(makeDirs(childDir), "makeDirs creates nested output directories");

    const std::string future = joinPath(childDir, "future.bin");
    check(pathIsWithin(future, root), "pathIsWithin accepts a future child path");
    check(pathIsWithin(root, root), "pathIsWithin accepts the root itself");
    check(!pathIsWithin("/tmp", root), "pathIsWithin rejects ancestors");
    check(!pathIsWithin(root + "-sibling/file.bin", root),
          "pathIsWithin rejects same-prefix sibling paths");

    const std::string first = uniquePath(childDir, "file.txt");
    FILE* fp = std::fopen(first.c_str(), "wb");
    check(fp != nullptr, "test can create a collision file");
    if (fp) std::fclose(fp);
    check(baseName(uniquePath(childDir, "file.txt")) == "file_1.txt",
          "uniquePath appends a numeric suffix before the extension");
}

}  // namespace

int main() {
    testBytesAccessors();
    testEncodingAndHashes();
    testSanitizers();
    testPathContainment();

    if (failures) {
        std::cerr << failures << " unit test failure(s)\n";
        return 1;
    }
    std::cout << "ghost_unit_tests passed\n";
    return 0;
}
