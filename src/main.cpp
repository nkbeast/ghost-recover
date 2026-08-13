// GHOST RECOVER — entry point.
//
// Runs either as a local web application (default) or headlessly from the
// command line, so the engine can be scripted and used over SSH instead of
// only through a browser.
#include "ghost/carve.h"
#include "ghost/decompress.h"
#include "ghost/disk.h"
#include "ghost/fs.h"
#include "ghost/jobs.h"
#include "ghost/recover.h"
#include "ghost/server.h"
#include "ghost/util.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace ghost;

void printUsage() {
    printf(
"GHOST RECOVER %s — data recovery suite\n"
"\n"
"USAGE\n"
"  ghost_recover [options]                     start the web interface\n"
"  ghost_recover <command> [args]              run headlessly\n"
"\n"
"SERVER OPTIONS\n"
"  --port N              listen on port N (default 3030)\n"
"  --listen ADDR         bind address (default 127.0.0.1; use 0.0.0.0 to expose)\n"
"  --output DIR          where recovered files are written\n"
"                        (default $GHOST_OUTPUT or ~/ghost-recover-output)\n"
"  --allow-writes        permit repair operations to modify the device\n"
"  --no-browser          do not open a browser window\n"
"  --web DIR             path to the web assets\n"
"  --takeover FILE       internal: claim the port from a running instance\n"
"\n"
"COMMANDS\n"
"  disks                                 list block devices\n"
"  detect  <device|image> [--offset N]   identify the filesystem\n"
"  parts   <device|image> [--deep]       list partitions (--deep finds deleted ones)\n"
"  scan    <device|image> [options]      list files, including deleted ones\n"
"  carve   <device|image> [options]      signature-carve into --out DIR\n"
"  recover <device|image> --out DIR      scan and write every recoverable file\n"
"  image   <device> --out FILE           clone to an image, tolerating bad sectors\n"
"  raid    <member> ... [--out FILE]     detect RAID parameters, optionally assemble\n"
"          use `missing` for a dead member, and --level/--chunk/--layout to\n"
"          state a geometry instead of detecting it\n"
"  repair  <device|image> [--action A] [--apply]\n"
"  carvers                               list carver signatures\n"
"\n"
"COMMON OPTIONS\n"
"  --offset N   start of the volume inside the device, in bytes\n"
"  --size N     length of the volume, in bytes\n"
"  --fs NAME    force a filesystem instead of auto-detecting\n"
"  --out DIR    output directory or file\n"
"  --limit N    show at most N rows (default 200)\n"
"  --max-files N  stop scanning after N files\n"
"  --deleted    only report deleted files\n"
"  --json       machine-readable output\n"
"\n"
"EXAMPLES\n"
"  ghost_recover                                  # open the GUI\n"
"  sudo ghost_recover parts /dev/sda --deep\n"
"  sudo ghost_recover scan /dev/sda2 --deleted\n"
"  sudo ghost_recover recover /dev/sda2 --out ~/rescued\n"
"  sudo ghost_recover image /dev/sdb --out ~/sdb.img\n",
        engineVersion());
}

struct Args {
    std::vector<std::string> positional;
    std::string get(const std::string& key, const std::string& def = "") const {
        for (size_t i = 0; i + 1 < raw.size(); i++)
            if (raw[i] == key) return raw[i + 1];
        return def;
    }
    i64 getInt(const std::string& key, i64 def) const {
        std::string v = get(key);
        if (v.empty()) return def;
        try { return std::stoll(v); } catch (...) { return def; }
    }
    bool has(const std::string& key) const {
        return std::find(raw.begin(), raw.end(), key) != raw.end();
    }
    std::vector<std::string> raw;
};

int cmdDisks(const Args&) {
    auto disks = detectDisks();
    if (disks.empty()) {
        printf("No block devices found (need read access to /sys/block).\n");
        return 1;
    }
    printf("%-14s %-12s %-10s %-28s %s\n", "DEVICE", "SIZE", "TYPE", "MODEL", "STATUS");
    for (const auto& d : disks) {
        printf("%-14s %-12s %-10s %-28s %s\n", d.device_path.c_str(),
               humanSize(d.size_bytes).c_str(), d.type.c_str(),
               d.display_name.substr(0, 28).c_str(),
               d.accessible ? "readable" : d.status_message.c_str());
    }
    return 0;
}

int cmdDetect(const Args& a) {
    if (a.positional.size() < 2) { printUsage(); return 2; }
    std::string err;
    auto disk = openTarget(a.positional[1], a.getInt("--offset", 0), a.getInt("--size", 0), &err);
    if (!disk) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    DetectResult d = detectFilesystem(*disk);
    printf("Target      : %s\n", a.positional[1].c_str());
    printf("Size        : %s (%lld bytes)\n", humanSize(disk->size()).c_str(),
           (long long)disk->size());
    printf("Detected    : %s\n", d.detected ? "yes" : "no");
    if (!d.filesystem.empty()) printf("Filesystem  : %s\n", d.filesystem.c_str());
    if (!d.label.empty())      printf("Label       : %s\n", d.label.c_str());
    if (!d.uuid.empty())       printf("UUID        : %s\n", d.uuid.c_str());
    if (d.block_size)          printf("Block size  : %lld\n", (long long)d.block_size);
    if (!d.note.empty())       printf("Note        : %s\n", d.note.c_str());
    if (!d.error.empty())      printf("Diagnostic  : %s\n", d.error.c_str());
    return d.detected ? 0 : 1;
}

int cmdParts(const Args& a) {
    if (a.positional.size() < 2) { printUsage(); return 2; }
    std::string err;
    auto disk = openTarget(a.positional[1], 0, 0, &err);
    if (!disk) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    PartitionOptions opt;
    opt.find_deleted = a.has("--deep");
    Progress prog;
    auto pr = scanPartitions(*disk, opt, prog);
    printf("Table       : %s\n", pr.partition_table.c_str());
    printf("Size        : %s, sector %lld\n", humanSize(pr.image_size).c_str(),
           (long long)pr.sector_size);
    if (!pr.error.empty()) printf("Note        : %s\n", pr.error.c_str());
    for (const auto& wn : pr.warnings) printf("Warning     : %s\n", wn.c_str());
    printf("\n%-4s %-14s %-14s %-12s %-10s %s\n", "#", "START", "SIZE", "FS", "STATUS", "TYPE");
    for (const auto& p : pr.partitions) {
        printf("%-4d %-14lld %-14s %-12s %-10s %s\n", p.entry, (long long)p.start_byte,
               humanSize(p.size_bytes).c_str(),
               p.filesystem.empty() ? "-" : p.filesystem.c_str(),
               p.fs_status.c_str(), p.type.c_str());
    }
    if (!pr.deleted_partitions.empty()) {
        printf("\nRecovered / unallocated regions:\n");
        for (const auto& p : pr.deleted_partitions) {
            printf("  %-14lld %-14s %-12s %s\n", (long long)p.start_byte,
                   humanSize(p.size_bytes).c_str(),
                   p.filesystem.empty() ? "-" : p.filesystem.c_str(), p.note.c_str());
        }
    }
    return 0;
}

int cmdScan(const Args& a) {
    if (a.positional.size() < 2) { printUsage(); return 2; }
    std::string err;
    auto disk = openTarget(a.positional[1], a.getInt("--offset", 0), a.getInt("--size", 0), &err);
    if (!disk) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    ScanOptions opt;
    // --limit caps how many rows are printed; the scan itself is not truncated,
    // so the reported totals always describe the whole volume.
    const i64 showLimit = a.getInt("--limit", 200);
    opt.max_files = a.getInt("--max-files", defaultMaxFiles());
    Progress prog;
    ScanResult r = scanVolume(*disk, a.get("--fs"), opt, prog);
    if (!r.ok) {
        fprintf(stderr, "scan failed: %s\n", r.error.c_str());
        return 1;
    }
    printf("Filesystem  : %s%s\n", r.filesystem.c_str(),
           r.label.empty() ? "" : (" (" + r.label + ")").c_str());
    if (!r.error.empty()) printf("Note        : %s\n", r.error.c_str());
    printf("Files       : %zu (%lld deleted)\n", r.files.size(), (long long)r.deleted_found);
    printf("Techniques  : ");
    for (size_t i = 0; i < r.techniques.size(); i++)
        printf("%s%s", r.techniques[i].c_str(), i + 1 < r.techniques.size() ? ", " : "\n");
    if (r.techniques.empty()) printf("(none)\n");
    for (const auto& [k, v] : r.stats) printf("  %-34s %lld\n", k.c_str(), (long long)v);

    bool deletedOnly = a.has("--deleted");
    printf("\n%-9s %-12s %-12s %-6s %s\n", "STATE", "SIZE", "RECOVERABLE", "CONF", "PATH");
    i64 shown = 0;
    for (const auto& f : r.files) {
        if (deletedOnly && !f.is_deleted) continue;
        if (f.is_dir) continue;
        printf("%-9s %-12s %-12s %-6.2f %s\n", f.is_deleted ? "deleted" : "live",
               humanSize(f.size).c_str(),
               humanSize(f.resident.empty() ? f.recoverable : (i64)f.resident.size()).c_str(),
               f.confidence, (f.path.empty() ? f.name : f.path).c_str());
        if (++shown >= showLimit) {
            printf("... (%lld more; use --limit to show them)\n",
                   (long long)((i64)r.files.size() - shown));
            break;
        }
    }
    return 0;
}

int cmdCarve(const Args& a) {
    if (a.positional.size() < 2) { printUsage(); return 2; }
    std::string err;
    auto disk = openTarget(a.positional[1], a.getInt("--offset", 0), a.getInt("--size", 0), &err);
    if (!disk) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    CarveOptions opt;
    opt.output_dir = a.get("--out", joinPath(defaultOutputRoot(), "carved"));
    opt.max_files = a.getInt("--limit", 20000);
    opt.text_carving = a.has("--text");
    if (!a.get("--categories").empty()) {
        std::string cats = a.get("--categories");
        size_t p = 0;
        while (p < cats.size()) {
            size_t c = cats.find(',', p);
            if (c == std::string::npos) c = cats.size();
            opt.categories.push_back(cats.substr(p, c - p));
            p = c + 1;
        }
    }
    Progress prog;
    printf("Carving %s into %s ...\n", a.positional[1].c_str(), opt.output_dir.c_str());
    CarveResult r = carveDevice(*disk, opt, prog);
    printf("Scanned     : %s\n", humanSize(r.bytes_scanned).c_str());
    printf("Signatures  : %lld\n", (long long)r.signatures_loaded);
    printf("Candidates  : %lld (rejected %lld, duplicates %lld)\n",
           (long long)r.candidates_seen, (long long)r.rejected, (long long)r.duplicates);
    printf("Recovered   : %lld files in %.1f s\n", (long long)r.files_recovered,
           r.elapsed_ms / 1000.0);
    if (!r.error.empty()) printf("Note        : %s\n", r.error.c_str());
    for (const auto& [fmt, n] : r.by_format) printf("  %-16s %lld\n", fmt.c_str(), (long long)n);
    if (a.has("--list")) {
        printf("\n%-14s %-12s %-16s %-6s %s\n", "OFFSET", "SIZE", "FORMAT", "ENTROPY", "FILE");
        for (const auto& f : r.files)
            printf("%-14lld %-12s %-16s %-6.2f %s\n", (long long)f.offset,
                   humanSize(f.size).c_str(), f.format.c_str(), f.entropy,
                   baseName(f.file).c_str());
    }
    return r.ok ? 0 : 1;
}

int cmdRecover(const Args& a) {
    if (a.positional.size() < 2) { printUsage(); return 2; }
    std::string out = a.get("--out");
    if (out.empty()) {
        fprintf(stderr, "error: --out DIR is required\n");
        return 2;
    }
    std::string err;
    auto disk = openTarget(a.positional[1], a.getInt("--offset", 0), a.getInt("--size", 0), &err);
    if (!disk) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    ScanOptions sopt;
    sopt.max_files = a.getInt("--limit", 500000);
    ExtractOptions eopt;
    eopt.output_dir = out;
    Progress prog;
    printf("Scanning %s ...\n", a.positional[1].c_str());
    ExtractResult r = recoverVolume(*disk, a.get("--fs"), sopt, eopt, prog);
    printf("Written     : %d files, %s\n", r.files_written, humanSize(r.bytes_written).c_str());
    if (r.files_failed) printf("Failed      : %d\n", r.files_failed);
    if (r.files_undecoded) {
        printf("Warning     : %d file(s) were written in the filesystem's compressed form and\n"
               "              are NOT usable as-is — this engine has no decoder for that codec.\n"
               "              They are marked still_compressed=yes in the manifest.\n",
               r.files_undecoded);
        for (size_t i = 0; i < r.undecoded.size() && i < 5; i++)
            printf("                %s\n", r.undecoded[i].c_str());
    }
    if (!r.error.empty()) printf("Error       : %s\n", r.error.c_str());
    return r.ok ? 0 : 1;
}

int cmdImage(const Args& a) {
    if (a.positional.size() < 2) { printUsage(); return 2; }
    std::string out = a.get("--out");
    if (out.empty()) { fprintf(stderr, "error: --out FILE is required\n"); return 2; }
    std::string err;
    auto disk = openTarget(a.positional[1], 0, 0, &err);
    if (!disk) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    ImageOptions opt;
    opt.output_path = out;
    opt.mapfile = a.get("--map", out + ".map");
    opt.retry_passes = a.getInt("--retries", 2);
    opt.start = a.getInt("--offset", 0);
    opt.length = a.getInt("--size", 0);
    Progress prog;
    printf("Imaging %s -> %s\n", a.positional[1].c_str(), out.c_str());
    ImageResult r = createImage(*disk, opt, prog);
    printf("Copied      : %s at %.1f MB/s\n", humanSize(r.bytes_copied).c_str(), r.rate_mb_s);
    printf("Unreadable  : %s in %lld regions\n", humanSize(r.bytes_bad).c_str(),
           (long long)r.bad_regions);
    if (!r.error.empty()) printf("Error       : %s\n", r.error.c_str());
    return r.ok ? 0 : 1;
}

int cmdRaid(const Args& a) {
    std::vector<std::string> members(a.positional.begin() + 1, a.positional.end());
    if (members.size() < 2) {
        fprintf(stderr, "error: give at least two member devices or images\n");
        return 2;
    }
    Progress prog;
    RaidLayout layout;

    // A dead member cannot be detected around — the assembled data is wrong
    // until parity fills the hole — so the geometry can be stated explicitly,
    // with `missing` standing in for the member that is gone (as mdadm does).
    const bool hasMissing =
        std::find(members.begin(), members.end(), std::string("missing")) != members.end();
    const std::string levelArg = a.get("--level");

    if (!levelArg.empty() || hasMissing) {
        layout.level = raidLevelFromString(levelArg.empty() ? "5" : levelArg);
        if (layout.level == RaidLevel::Unknown) {
            fprintf(stderr, "error: --level must be one of linear, 0, 1, 5, 6, 10\n");
            return 2;
        }
        layout.chunk_size = a.getInt("--chunk", 65536);
        layout.parity_layout = a.get("--layout", "left-symmetric");
        layout.members = (int)members.size();
        layout.detected_from = "manual";
        layout.confidence = 1.0;
        for (const auto& m : members) {
            RaidMember rm;
            if (m == "missing") { rm.present = false; }
            else { rm.path = m; rm.present = true; }
            layout.disks.push_back(rm);
        }
        if (levelArg.empty())
            printf("note: assuming RAID 5 for the degraded array; pass --level to change it\n");
    } else {
        layout = detectRaidLayout(members, prog);
    }
    printf("Level       : %s\n", raidLevelName(layout.level));
    printf("Chunk size  : %lld bytes\n", (long long)layout.chunk_size);
    printf("Members     : %d\n", layout.members);
    printf("Layout      : %s\n", layout.parity_layout.c_str());
    printf("Source      : %s (confidence %.2f)%s\n", layout.detected_from.c_str(),
           layout.confidence, layout.ambiguous ? "  [AMBIGUOUS]" : "");
    for (const auto& alt : layout.alternatives)
        printf("  also fits  : %s\n", alt.c_str());
    for (const auto& d : layout.disks)
        printf("  role %-3d %-40s offset %lld\n", d.role, d.path.c_str(),
               (long long)d.data_offset);
    for (const auto& n : layout.notes) printf("  note: %s\n", n.c_str());
    if (layout.level == RaidLevel::Unknown) return 1;

    std::string out = a.get("--out");
    if (!out.empty()) {
        printf("\nAssembling into %s ...\n", out.c_str());
        RaidBuildResult r = assembleRaid(layout, out, a.getInt("--size", 0), prog);
        printf("Written     : %s\n", humanSize(r.bytes_written).c_str());
        if (r.stripes_reconstructed)
            printf("Rebuilt     : %lld stripe unit(s) from parity\n",
                   (long long)r.stripes_reconstructed);
        if (!r.error.empty()) printf("Error       : %s\n", r.error.c_str());
        return r.ok ? 0 : 1;
    }
    printf("\nAdd --out FILE to write the assembled array to an image.\n");
    return 0;
}

int cmdRepair(const Args& a) {
    if (a.positional.size() < 2) { printUsage(); return 2; }
    std::string err;
    auto disk = openTarget(a.positional[1], a.getInt("--offset", 0), a.getInt("--size", 0), &err);
    if (!disk) { fprintf(stderr, "error: %s\n", err.c_str()); return 1; }
    RepairOptions opt;
    opt.apply = a.has("--apply");
    RepairResult r = repairVolume(*disk, a.get("--action"), opt);
    printf("Action      : %s\n", r.action.c_str());
    printf("Result      : %s%s\n", r.ok ? "ok" : "failed", r.applied ? " (written)" : "");
    if (!r.detail.empty()) printf("Detail      : %s\n", r.detail.c_str());
    if (!r.error.empty())  printf("Error       : %s\n", r.error.c_str());
    for (const auto& s : r.steps) printf("  - %s\n", s.c_str());
    if (!opt.apply && r.ok)
        printf("\nThis was a dry run. Add --apply to write the change (image the disk first).\n");
    return r.ok ? 0 : 1;
}

int cmdCarvers(const Args&) {
    const auto& reg = carverRegistry();
    printf("%zu carver signatures across %zu categories\n\n", reg.size(),
           carverCategories().size());
    printf("%-18s %-12s %-12s %-10s %s\n", "FORMAT", "EXT", "CATEGORY", "MAXSIZE", "VALIDATED");
    for (const auto& c : reg) {
        printf("%-18s %-12s %-12s %-10s %s\n", c.name.c_str(), c.ext.c_str(),
               c.category.c_str(), humanSize(c.max_size).c_str(),
               c.validator ? "yes" : "no");
    }
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);

    // glibc inflates one ~64 MB virtual malloc arena per thread (up to 8x
    // cores); on a 1 GiB box with strict overcommit that reservation alone
    // exhausts the address space before any real work. Cap the arenas early —
    // the env var is read when the first extra arena is created.
    {
        const i64 ramGB = ghost::systemRamKB() / (1024 * 1024);
        if (ramGB > 0 && ramGB <= 4)
            ::setenv("MALLOC_ARENA_MAX", std::to_string(std::clamp<i64>(ramGB, 2, 4)).c_str(), 1);
    }

    Args args;
    for (int i = 1; i < argc; i++) {
        std::string s = argv[i];
        args.raw.push_back(s);
        if (!s.empty() && s[0] != '-') {
            // Values that follow an option are not positional arguments.
            if (i > 1) {
                std::string prev = argv[i - 1];
                static const char* kValueOpts[] = {"--port", "--listen", "--output", "--web",
                                                  "--offset", "--size", "--fs", "--out",
                                                  "--limit", "--action", "--map", "--retries",
                                                  "--categories", "--takeover", "--level", "--chunk",
                                                  "--layout", nullptr};
                bool isValue = false;
                for (int k = 0; kValueOpts[k]; k++) if (prev == kValueOpts[k]) isValue = true;
                if (isValue) continue;
            }
            args.positional.push_back(s);
        }
    }

    if (args.has("--help") || args.has("-h")) { printUsage(); return 0; }
    if (args.has("--version")) { printf("%s\n", ghost::engineVersion()); return 0; }

    if (!args.positional.empty()) {
        const std::string& cmd = args.positional[0];
        if (cmd == "disks")   return cmdDisks(args);
        if (cmd == "detect")  return cmdDetect(args);
        if (cmd == "parts" || cmd == "partitions") return cmdParts(args);
        if (cmd == "scan")    return cmdScan(args);
        if (cmd == "carve")   return cmdCarve(args);
        if (cmd == "recover") return cmdRecover(args);
        if (cmd == "image")   return cmdImage(args);
        if (cmd == "raid")    return cmdRaid(args);
        if (cmd == "repair")  return cmdRepair(args);
        if (cmd == "carvers") return cmdCarvers(args);
        if (cmd == "selftest") return ghost::selftest::run();
        fprintf(stderr, "unknown command '%s'\n\n", cmd.c_str());
        printUsage();
        return 2;
    }

    ghost::ServerConfig cfg;
    cfg.port = (int)args.getInt("--port", 3030);
    cfg.bind_address = args.get("--listen", "127.0.0.1");
    // Only loopback binds get the strict local-only safeguards (loopback
    // Host/Origin gate, sudo-password veto happens before any password is
    // accepted, etc.). Binding a LAN/WAN address or another hostname silently
    // reaching only the browser checks would leave the API wide open on the
    // network while pretending to be "local".
    auto isLoopbackBind = [](const std::string& b) {
        return b == "127.0.0.1" || b == "::1" || b == "[::1]" || b == "localhost";
    };
    cfg.allow_remote = !isLoopbackBind(cfg.bind_address);
    cfg.output_root = args.get("--output");
    cfg.web_root = args.get("--web");
    cfg.allow_repair_writes = args.has("--allow-writes");
    cfg.takeover_file = args.get("--takeover");

    if (args.has("--json")) {
        printf("{\"version\":\"%s\",\"filesystems\":%zu,\"carvers\":%zu,\"port\":%d,"
               "\"listen\":\"%s\"}\n",
               ghost::engineVersion(), ghost::filesystemRegistry().size(),
               ghost::carverRegistry().size(), cfg.port, cfg.bind_address.c_str());
    } else {
        printf("\n");
        printf("  GHOST RECOVER  %s\n", ghost::engineVersion());
        printf("  %zu filesystems · %zu carver signatures · RAID · imaging · repair\n\n",
               ghost::filesystemRegistry().size(), ghost::carverRegistry().size());
    }

    if (!args.has("--no-browser") && cfg.takeover_file.empty()) {
        cfg.open_browser = true;
    }

    return ghost::startServer(cfg);
}
