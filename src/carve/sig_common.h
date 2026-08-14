// GHOST RECOVER — shared carver plumbing.
//
// Everything both the per-category sig_*.cpp files and the registry
// aggregator (signatures.cpp) need: byte-string builders, size constants,
// spec constructors, the walks* helpers and the validators referenced across
// translation units (each validator is defined in exactly one sig_*.cpp file).
#pragma once
#include "ghost/carve.h"

#include <cstring>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>

namespace ghost {

using Registry = std::vector<CarveSpec>;

inline std::vector<u8> B(std::initializer_list<int> v) {
    std::vector<u8> o;
    o.reserve(v.size());
    for (int x : v) o.push_back((u8)x);
    return o;
}
inline std::vector<u8> S(const char* s) {
    return std::vector<u8>(reinterpret_cast<const u8*>(s),
                           reinterpret_cast<const u8*>(s) + std::strlen(s));
}
// ASCII spelled out as UTF-16LE — OLE2 stream names are stored that way, and
// writing them as a C string would terminate at the first embedded NUL.
inline std::vector<u8> U16(const char* s) {
    std::vector<u8> o;
    for (const char* p = s; *p; ++p) { o.push_back((u8)*p); o.push_back(0); }
    return o;
}

inline constexpr i64 KB = 1024;
inline constexpr i64 MB = 1024 * 1024;
inline constexpr i64 GB = 1024 * MB;

// ---- cross-TU validator declarations (defined in sig_*.cpp) ----
i64 v7z(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vAac(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vAc3(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vAmr(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vAndroidBoot(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vAr(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vArc(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vArj(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vAsf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vAu(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vBmp(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vBzip2(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vCab(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vBik(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vCaf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vClass(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vCpio(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vCrw(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vDbf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vDer(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vDex(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vDmp(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vDts(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vEbml(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vElf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vEvtx(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vEwf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vFlac(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vFlv(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vGif(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vGlb(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vGpg(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vGzip(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vIco(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vIff(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vIso(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vIvf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vJpeg(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vJxl(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMachO(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMat(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vLzmaAlone(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMidi(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMp3(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMpc(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vNes(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vNsv(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMp4(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMpegPs(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMpegTs(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMpegVes(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vMxf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vNpy(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vOgg(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPak(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPnm(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vOle2(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPcap(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPcapng(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPcx(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPdf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPe(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPickle(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPlistBin(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPng(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPsd(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vPyc(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vQcow(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vQed(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vQoi(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vRar(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vRegf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vRiff(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vSfnt(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vSgi(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vSqlite(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vStlAscii(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vSwf(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vSvgXml(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vTar(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vText(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vTiff(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vTtc(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vVdi(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vVhd(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vVhdx(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vVoc(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vWad(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vWasm(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vWoff(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vWtv(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vXpm(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vXz(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vZip(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);
i64 vZws(ByteSource& s, i64 off, i64 max, const CarveSpec& spec);

CarveSpec mk(const char* name, const char* ext, const char* cat, std::vector<u8> magic,
             i64 maxSize, SizeMode mode = SizeMode::Heuristic, SizeFn fn = nullptr);
CarveSpec& withConfirm(CarveSpec& c, std::vector<u8> confirm, int atOffset, int window = 4096);
bool walksWholeFile(SizeFn fn);
bool walksToBoundary(SizeFn fn);

// ---- per-category registration (defined in sig_<category>.cpp) ----
void registerImages(Registry& r);
void registerVideo(Registry& r);
void registerAudio(Registry& r);
void registerDocuments(Registry& r);
void registerEmail(Registry& r);
void registerArchives(Registry& r);
void registerDatabases(Registry& r);
void registerCrypto(Registry& r);
void registerExecutables(Registry& r);
void registerForensic(Registry& r);
void registerVm(Registry& r);
void registerFonts(Registry& r);
void registerMisc(Registry& r);
void registerCode(Registry& r);

}  // namespace ghost
