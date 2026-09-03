// GHOST RECOVER — block device enumeration via sysfs.
#include "ghost/disk.h"

#include "ghost/util.h"

#include <algorithm>
#include <climits>
#include <fstream>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ghost {

namespace {

std::string readAttr(const std::string& path) {
    std::ifstream f(path);
    std::string s;
    std::getline(f, s);
    return trim(s);
}

u64 readAttrU64(const std::string& path) {
    std::ifstream f(path);
    u64 v = 0;
    f >> v;
    return v;
}

bool isVirtualOrUninteresting(const std::string& name) {
    static const char* kSkip[] = {"ram", "zram", "loop", "dm-", "md", "pmem", "fd", "sr", "nbd", nullptr};
    for (int i = 0; kSkip[i]; i++)
        if (startsWith(name, kSkip[i])) return true;
    return false;
}

int countPartitions(const std::string& sysPath, const std::string& name) {
    int n = 0;
    DIR* d = opendir(sysPath.c_str());
    if (!d) return 0;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        std::string sub = e->d_name;
        if (sub == "." || sub == "..") continue;
        if (!startsWith(sub, name)) continue;
        // A partition is the disk name, an optional "p" separator (NVMe and
        // mmcblk name theirs "nvme0n1p1" / "mmcblk0p1"), then digits only —
        // "sdaa1" belongs to the disk "sdaa", not to "sda".
        if (sub.size() <= name.size()) continue;
        size_t i = name.size();
        if (sub[i] == 'p' || sub[i] == 'P') i++;
        for (; i < sub.size() && ::isdigit((unsigned char)sub[i]); i++) {}
        if (i < sub.size()) continue;
        if (fileExists(sysPath + "/" + sub + "/partition")) n++;
    }
    closedir(d);
    return n;
}

std::vector<std::string> readHolders(const std::string& sysPath) {
    std::vector<std::string> out;
    DIR* d = opendir((sysPath + "/holders").c_str());
    if (!d) return out;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        std::string s = e->d_name;
        if (s == "." || s == "..") continue;
        out.push_back(s);
    }
    closedir(d);
    return out;
}

}  // namespace

std::vector<DiskInfo> detectDisks() {
    std::vector<DiskInfo> disks;
    DIR* dir = opendir("/sys/block");
    if (!dir) return disks;

    struct dirent* ent;
    while ((ent = readdir(dir)) != nullptr) {
        std::string name = ent->d_name;
        if (name.empty() || name == "." || name == "..") continue;
        if (isVirtualOrUninteresting(name)) continue;

        std::string sysPath = "/sys/block/" + name;
        struct stat st{};
        if (stat(sysPath.c_str(), &st) != 0) continue;

        DiskInfo d;
        d.name = name;
        d.device_path = "/dev/" + name;

        u64 sectors = readAttrU64(sysPath + "/size");
        d.logical_sector  = (i64)std::max<u64>(512, readAttrU64(sysPath + "/queue/logical_block_size"));
        d.physical_sector = (i64)std::max<u64>(512, readAttrU64(sysPath + "/queue/physical_block_size"));
        // /sys/block/*/size is always in 512-byte units regardless of the
        // device's logical sector size. Guard the u64 multiply against
        // i64 overflow: a hostile virtual device could report an absurd
        // sector count and the cast would be UB.
        if (sectors > (u64)INT64_MAX / 512) d.size_bytes = INT64_MAX;
        else d.size_bytes = (i64)(sectors * 512);
        if (d.size_bytes <= 0) continue;
        d.size_gb = d.size_bytes / 1073741824.0;

        d.removable  = readAttr(sysPath + "/removable") == "1";
        d.rotational = readAttr(sysPath + "/queue/rotational") == "1";
        d.vendor = readAttr(sysPath + "/device/vendor");
        d.model  = readAttr(sysPath + "/device/model");
        d.serial = readAttr(sysPath + "/device/serial");
        if (d.model.empty()) d.model = readAttr(sysPath + "/device/name");        // NVMe
        if (d.serial.empty()) d.serial = readAttr(sysPath + "/device/wwid");
        d.wwid = readAttr(sysPath + "/wwid");
        d.transport = readAttr(sysPath + "/device/transport");
        d.partition_count = countPartitions("/sys/block", name);
        d.holders = readHolders(sysPath);
        for (const auto& h : d.holders)
            if (startsWith(h, "md")) d.is_raid_member = true;

        if (startsWith(name, "nvme"))        { d.type = "nvme";   d.type_label = "NVMe SSD"; }
        else if (startsWith(name, "mmcblk")) { d.type = "sdcard"; d.type_label = "SD / eMMC Card"; }
        else if (startsWith(name, "vd"))     { d.type = "virtio"; d.type_label = "Virtual Disk (virtio)"; }
        else if (startsWith(name, "xvd"))    { d.type = "virtio"; d.type_label = "Virtual Disk (Xen)"; }
        else if (d.removable)                { d.type = "usb";    d.type_label = "USB / Removable"; }
        else if (d.rotational)               { d.type = "hdd";    d.type_label = "Hard Disk (rotational)"; }
        else                                 { d.type = "ssd";    d.type_label = "SSD"; }

        std::string vm = trim(d.vendor + " " + d.model);
        d.display_name = vm.empty() ? name : vm;

        if (::access(d.device_path.c_str(), R_OK) == 0) {
            d.accessible = true;
        } else {
            d.accessible = false;
            struct stat ds{};
            if (::stat(d.device_path.c_str(), &ds) != 0)
                d.status_message = "Device node " + d.device_path + " is missing.";
            else
                d.status_message = "Permission denied on " + d.device_path +
                                   " — run the engine as root or add your user to the 'disk' group.";
        }
        disks.push_back(std::move(d));
    }
    closedir(dir);

    std::sort(disks.begin(), disks.end(),
              [](const DiskInfo& a, const DiskInfo& b) { return a.name < b.name; });
    return disks;
}

}  // namespace ghost
