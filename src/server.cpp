// GHOST//RECOVER — HTTP API.
//
// Rewritten around a job model. Scans and carves now run on worker threads and
// the browser polls for progress, instead of blocking an HTTP handler that the
// socket timeout would kill on any real workload. Results stay in memory and
// are paged out to the UI, so a scan that finds half a million files no longer
// has to be serialised into one enormous JSON document.
//
// Also fixed here: /api/file and /api/hex used to serve any path on the host
// that the process could read, and the preview cache was hard-coded to a
// directory on the original author's machine.
#include "ghost/server.h"

#include "ghost/carve.h"
#include "ghost/disk.h"
#include "ghost/fs.h"
#include "ghost/io.h"
#include "ghost/jobs.h"
#include "ghost/json.h"
#include "ghost/recover.h"
#include "ghost/util.h"

#include <httplib.h>

#include <algorithm>
#include <fstream>
#include <mutex>
#include <unordered_map>

#include <chrono>
#include <thread>

#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace ghost {

namespace {

const char* kVersion = "3.0.0";

std::string g_outputRoot;
std::mutex  g_outputMutex;
bool        g_allowWrites = false;

// Set while a privileged copy of this process is being handed the port.
std::string       g_handoverToken;
std::string       g_handoverFile;
httplib::Server*  g_server = nullptr;
std::atomic<bool> g_handedOver{false};

// Graceful shutdown. /api/shutdown and the signal thread both land here:
// stop() makes httplib's listen() return, after which startServer returns and
// the process exits, releasing the port for the next start.
void requestEngineShutdown() {
    if (g_server) g_server->stop();
}

// True when a GHOST//RECOVER engine is answering health on the given port.
// Used to reconnect to an already-running instance instead of failing.
bool liveEngineOnPort(int port) {
    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(1, 0);
    cli.set_read_timeout(2, 0);
    auto r = cli.Get("/api/health");
    return r && r->status == 200 &&
           r->body.find("\"service\":\"ghost-recover\"") != std::string::npos;
}

// SIGINT/SIGTERM -> graceful stop. httplib's stop() is not async-signal-safe,
// so the signals are blocked process-wide and a dedicated thread consumes them
// with sigwait() instead of using a raw handler. The mask is inherited by
// every thread spawned after installShutdownSignals(), which is what makes the
// sigwait reliable. Called only from startServer, so the CLI scan/carve modes
// keep their default signal behaviour.
void installShutdownSignals() {
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
    std::thread([set]() {
        for (;;) {
            int sig = 0;
            if (sigwait(&set, &sig) != 0) continue;
            fprintf(stderr, "shutdown requested (signal %d)\n", sig);
            requestEngineShutdown();
        }
    }).detach();
}

// State of an in-flight elevation attempt. pkexec and sudo both *exec* the
// target on success, so the child process only ever exits on its own if the
// authentication was declined or failed — which makes its exit a precise
// signal, rather than waiting for a timeout.
struct ElevationAttempt {
    std::atomic<bool> pending{false};
    std::atomic<bool> child_exited{false};
    std::atomic<int>  exit_code{0};
    std::string       method;
};
ElevationAttempt g_elevation;

// ---------------------------------------------------------------------------
// Result store: keeps the full result of a job in memory so the UI can page
// through it, preview individual files and extract a selection afterwards.
// ---------------------------------------------------------------------------
struct StoredResult {
    std::string kind;                 // "scan" | "carve" | "deep"
    std::string target;
    i64 offset = 0;
    i64 length = 0;
    std::string filesystem;
    ScanResult  scan;
    CarveResult carve;
    std::vector<RecoveredFile> files;   // unified view used by the UI
};

class ResultStore {
public:
    static ResultStore& instance() {
        static ResultStore s;
        return s;
    }
    void put(const std::string& jobId, std::shared_ptr<StoredResult> r) {
        std::lock_guard<std::mutex> lk(mu_);
        results_[jobId] = std::move(r);
        order_.erase(std::remove(order_.begin(), order_.end(), jobId), order_.end());
        order_.push_back(jobId);
        // A scan result can be hundreds of megabytes, so keep only the most
        // recent few. Evicting after recording the new id means the entry just
        // added can never be the one dropped.
        while (order_.size() > 16) {
            results_.erase(order_.front());
            order_.erase(order_.begin());
        }
    }
    std::shared_ptr<StoredResult> get(const std::string& jobId) const {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = results_.find(jobId);
        return it == results_.end() ? nullptr : it->second;
    }
    void drop(const std::string& jobId) {
        std::lock_guard<std::mutex> lk(mu_);
        results_.erase(jobId);
        order_.erase(std::remove(order_.begin(), order_.end(), jobId), order_.end());
    }

private:
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<StoredResult>> results_;
    std::vector<std::string> order_;
};

// ---------------------------------------------------------------------------
std::string mimeForExtension(const std::string& extRaw) {
    std::string e = toLower(extRaw);
    static const std::map<std::string, std::string> kMap = {
        {"jpg","image/jpeg"},{"jpeg","image/jpeg"},{"png","image/png"},{"gif","image/gif"},
        {"bmp","image/bmp"},{"webp","image/webp"},{"tif","image/tiff"},{"tiff","image/tiff"},
        {"ico","image/x-icon"},{"svg","image/svg+xml"},{"heic","image/heif"},{"heif","image/heif"},
        {"avif","image/avif"},{"psd","image/vnd.adobe.photoshop"},{"jp2","image/jp2"},
        {"mp4","video/mp4"},{"m4v","video/x-m4v"},{"mkv","video/x-matroska"},
        {"webm","video/webm"},{"avi","video/x-msvideo"},{"mov","video/quicktime"},
        {"flv","video/x-flv"},{"3gp","video/3gpp"},{"ts","video/mp2t"},{"mpg","video/mpeg"},
        {"mpeg","video/mpeg"},{"wmv","video/x-ms-wmv"},{"asf","video/x-ms-asf"},
        {"mp3","audio/mpeg"},{"wav","audio/wav"},{"flac","audio/flac"},{"ogg","audio/ogg"},
        {"oga","audio/ogg"},{"opus","audio/ogg"},{"spx","audio/ogg"},{"m4a","audio/mp4"},
        {"aac","audio/aac"},{"aiff","audio/aiff"},{"aifc","audio/aiff"},{"ac3","audio/ac3"},
        {"amr","audio/amr"},{"mid","audio/midi"},{"wma","audio/x-ms-wma"},{"au","audio/basic"},
        {"pdf","application/pdf"},{"json","application/json"},{"xml","text/xml"},
        {"html","text/html"},{"htm","text/html"},{"css","text/css"},{"js","text/javascript"},
        {"csv","text/csv"},{"zip","application/zip"},{"gz","application/gzip"},
        {"7z","application/x-7z-compressed"},{"rar","application/vnd.rar"},
        {"tar","application/x-tar"},{"doc","application/msword"},
        {"docx","application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
        {"xls","application/vnd.ms-excel"},
        {"xlsx","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
        {"ppt","application/vnd.ms-powerpoint"},
        {"pptx","application/vnd.openxmlformats-officedocument.presentationml.presentation"},
        {"epub","application/epub+zip"},{"rtf","application/rtf"},{"sqlite","application/vnd.sqlite3"},
    };
    auto it = kMap.find(e);
    if (it != kMap.end()) return it->second;
    static const char* kTextExts[] = {"txt","md","log","py","sh","yml","yaml","ini","conf","c",
                                      "cpp","h","hpp","rs","go","java","rb","php","sql","toml",
                                      "env","mbox","eml","pem","service","gitconfig","tex",
                                      "dockerfile","cmake", nullptr};
    for (int i = 0; kTextExts[i]; i++) if (e == kTextExts[i]) return "text/plain; charset=utf-8";
    return "application/octet-stream";
}

std::string errorJson(const std::string& message, const std::string& hint = "") {
    json::Writer w;
    w.beginObject().kv("ok", false).kv("error", message);
    if (!hint.empty()) w.kv("hint", hint);
    w.endObject();
    return w.str();
}

void writeFile(json::Writer& w, const RecoveredFile& f, size_t index) {
    w.beginObject();
    w.kv("index", (i64)index);
    w.kv("id", (i64)f.id);
    w.kv("name", f.name);
    w.kv("path", f.path);
    w.kv("ext", extensionOf(f.name));
    w.kv("size", f.size);
    w.kv("recoverable", f.recoverable);
    w.kv("deleted", f.is_deleted);
    w.kv("dir", f.is_dir);
    w.kv("kind", fileKindName(f.kind));
    w.kv("method", f.method);
    w.kv("confidence", f.confidence);
    w.kv("mtime", f.mtime);
    w.kv("mtime_iso", isoTime(f.mtime));
    w.kv("compressed", f.is_compressed);
    w.kv("encrypted", f.is_encrypted);
    w.kv("ads", f.is_adstream);
    w.kv("offset", f.extents.empty() ? (i64)0 : f.extents.front().offset);
    w.kv("resident", (i64)f.resident.size());
    w.endObject();
}

void writeScanSummary(json::Writer& w, const ScanResult& s) {
    w.key("scan").beginObject();
    w.kv("ok", s.ok);
    if (!s.error.empty()) w.kv("error", s.error);
    w.kv("filesystem", s.filesystem);
    w.kv("label", s.label);
    w.kv("uuid", s.uuid);
    w.kv("block_size", s.block_size);
    w.kv("total_blocks", s.total_blocks);
    w.kv("free_blocks", s.free_blocks);
    w.kv("total_inodes", s.total_inodes);
    w.kv("free_inodes", s.free_inodes);
    w.kv("volume_size", s.volume_size);
    w.kv("file_count", (i64)s.files.size());
    w.kv("deleted_found", s.deleted_found);
    w.key("techniques").beginArray();
    for (const auto& t : s.techniques) w.value(t);
    w.endArray();
    w.key("stats").beginObject();
    for (const auto& [k, v] : s.stats) w.kv(k, v);
    w.endObject();
    w.endObject();
}

void writeCarveSummary(json::Writer& w, const CarveResult& c) {
    w.key("carve").beginObject();
    w.kv("ok", c.ok);
    if (!c.error.empty()) w.kv("error", c.error);
    w.kv("image_size", c.image_size);
    w.kv("bytes_scanned", c.bytes_scanned);
    w.kv("signatures_loaded", c.signatures_loaded);
    w.kv("candidates_seen", c.candidates_seen);
    w.kv("rejected", c.rejected);
    w.kv("duplicates", c.duplicates);
    w.kv("files_recovered", c.files_recovered);
    w.kv("elapsed_ms", c.elapsed_ms);
    w.key("by_format").beginObject();
    for (const auto& [k, v] : c.by_format) w.kv(k, v);
    w.endObject();
    w.key("by_category").beginObject();
    for (const auto& [k, v] : c.by_category) w.kv(k, v);
    w.endObject();
    w.endObject();
}

void writePartition(json::Writer& w, const PartitionInfo& p) {
    w.beginObject();
    w.kv("entry", p.entry);
    w.kv("table", p.table);
    w.kv("type", p.type);
    w.kv("type_guid", p.type_guid);
    w.kv("uuid", p.uuid);
    w.kv("status", p.status);
    w.kv("fs_status", p.fs_status);
    w.kv("filesystem", p.filesystem);
    w.kv("label", p.label);
    w.kv("fs_uuid", p.fs_uuid);
    w.kv("name", p.name);
    w.kv("note", p.note);
    w.kv("start_lba", p.start_lba);
    w.kv("size_lba", p.size_lba);
    w.kv("start_byte", p.start_byte);
    w.kv("size_bytes", p.size_bytes);
    w.kv("size_human", humanSize(p.size_bytes));
    w.kv("bootable", p.bootable);
    w.kv("recovered", p.recovered);
    w.kv("confidence", p.confidence);
    w.endObject();
}

RecoveredFile carvedToRecovered(const CarvedFile& c, size_t index) {
    RecoveredFile f;
    f.id = (u64)index;
    f.name = baseName(c.file.empty() ? (c.format + "_" + std::to_string(c.offset) + "." + c.ext)
                                     : c.file);
    f.path = "/" + c.category + "/" + f.name;
    f.size = c.size;
    f.recoverable = c.size;
    f.extents = c.extents;
    f.method = "carve:" + c.format;
    f.confidence = c.confidence;
    f.is_deleted = true;
    return f;
}

// Reads a body parameter set, shared by every endpoint that targets a volume.
struct Target {
    std::string path;
    i64 offset = 0;
    i64 length = 0;
    std::string filesystem;
};

Target readTarget(const json::Value& body) {
    Target t;
    t.path = body.getStr("image_path");
    if (t.path.empty()) t.path = body.getStr("path");
    t.offset = body.getInt("offset", 0);
    t.length = body.getInt("partition_size", body.getInt("length", 0));
    t.filesystem = body.getStr("filesystem");
    return t;
}

ScanOptions readScanOptions(const json::Value& body) {
    ScanOptions o;
    o.deep          = body.getBool("deep", true);
    o.journal       = body.getBool("journal", true);
    o.slack         = body.getBool("slack", true);
    o.orphans       = body.getBool("orphans", true);
    o.include_live  = body.getBool("include_live", true);
    o.resolve_paths = body.getBool("resolve_paths", true);
    o.max_files     = body.getInt("max_files", 500000);
    if (o.max_files < 1) o.max_files = 1;
    if (o.max_files > 5000000) o.max_files = 5000000;
    return o;
}

CarveOptions readCarveOptions(const json::Value& body, const std::string& defaultDir) {
    CarveOptions o;
    o.output_dir     = body.getStr("output_dir", defaultDir);
    o.max_files      = body.getInt("max_files", 20000);
    o.min_file_size  = body.getInt("min_file_size", 32);
    o.write_files    = body.getBool("write_files", true);
    o.compute_hashes = body.getBool("compute_hashes", true);
    o.validate       = body.getBool("validate", true);
    o.dedup          = body.getBool("dedup", true);
    o.text_carving   = body.getBool("text_carving", false);
    o.skip_allocated = body.getBool("unallocated_only", false);
    o.threads        = (int)body.getInt("threads", 0);
    if (const json::Value* cats = body.getArray("categories"))
        for (const auto& v : cats->arr) o.categories.push_back(v.asStr());
    if (const json::Value* exts = body.getArray("extensions"))
        for (const auto& v : exts->arr) o.extensions.push_back(v.asStr());
    if (o.max_files < 1) o.max_files = 1;
    if (o.max_files > 500000) o.max_files = 500000;
    return o;
}

std::string webRootPath(const std::string& configured) {
    std::vector<std::string> candidates;
    if (!configured.empty()) candidates.push_back(configured);
    candidates.push_back("web");
    candidates.push_back("ghost-recover/web");
    char exe[4096] = {0};
    ssize_t n = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        std::string dir = dirName(std::string(exe, (size_t)n));
        candidates.push_back(joinPath(dir, "web"));
        candidates.push_back(joinPath(dirName(dir), "web"));
        candidates.push_back(joinPath(dirName(dirName(dir)), "web"));
        candidates.push_back(joinPath(dir, "../share/ghost-recover/web"));
    }
    candidates.push_back("/usr/share/ghost-recover/web");
    candidates.push_back("/usr/local/share/ghost-recover/web");
    if (const char* home = ::getenv("HOME")) {
        candidates.push_back(joinPath(home, ".local/share/ghost-recover/web"));
        candidates.push_back(joinPath(home, "ghost-recover/web"));
    }
    for (const auto& c : candidates)
        if (fileExists(joinPath(c, "index.html"))) return c;
    return {};
}

}  // namespace

// ---------------------------------------------------------------------------
const char* engineVersion() { return kVersion; }

const std::string& outputRoot() {
    std::lock_guard<std::mutex> lk(g_outputMutex);
    if (g_outputRoot.empty()) g_outputRoot = defaultOutputRoot();
    return g_outputRoot;
}

void setOutputRoot(const std::string& p) {
    std::lock_guard<std::mutex> lk(g_outputMutex);
    g_outputRoot = p;
}

// ---------------------------------------------------------------------------
// Privilege elevation
//
// Physical disks are unreadable without root, which is the single most common
// reason a recovery attempt stops before it starts. Instead of telling the user
// to quit and re-run under sudo, the running instance launches a privileged
// copy of itself and hands it the listening port, so the browser reconnects to
// the same URL and the session continues.
//
// Order of preference:
//   1. pkexec  — polkit shows the desktop's own authentication dialog and the
//                password never passes through this process at all.
//   2. sudo, already authorised (no password needed).
//   3. sudo -S with a password the user typed into the interface. Only offered
//      when the first two are unavailable; the password is written straight to
//      sudo's stdin and is never stored, logged or echoed back.
//
// The handover is driven by the *new* process: it only asks the old one to
// stand down once it is actually running as root, so a cancelled authentication
// leaves the original session untouched.
// ---------------------------------------------------------------------------
namespace {

bool haveExecutable(const char* name) {
    const char* path = ::getenv("PATH");
    if (!path) path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    std::string p(path);
    size_t start = 0;
    while (start <= p.size()) {
        size_t end = p.find(':', start);
        if (end == std::string::npos) end = p.size();
        std::string dir = p.substr(start, end - start);
        if (!dir.empty() && ::access(joinPath(dir, name).c_str(), X_OK) == 0) return true;
        start = end + 1;
    }
    return false;
}

// `sudo -n true` succeeds only when sudo needs no password right now.
bool sudoWorksWithoutPassword() {
    pid_t pid = ::fork();
    if (pid < 0) return false;
    if (pid == 0) {
        int devnull = ::open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::dup2(devnull, STDOUT_FILENO);
            ::dup2(devnull, STDERR_FILENO);
        }
        ::execlp("sudo", "sudo", "-n", "true", (char*)nullptr);
        ::_exit(127);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) != pid) return false;
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// ---------------------------------------------------------------------------
// Browser launch (kept in the server so the page is only opened once the port
// actually answers; the old code fired the browser one second after the
// process started, which on a slow bind produced "localhost refused").
// ---------------------------------------------------------------------------
int findBrowser(char* buf, size_t bufsize) {
    static const char* kBrowsers[] = {"google-chrome", "google-chrome-stable", "chromium",
                                      "chromium-browser", "brave-browser", "microsoft-edge",
                                      "firefox", "xdg-open", nullptr};
    const char* pathEnv = getenv("PATH");
    if (!pathEnv) return 0;
    std::vector<std::string> dirs;
    const char* p = pathEnv;
    while (*p) {
        const char* sep = strchr(p, ':');
        dirs.push_back(sep ? std::string(p, (size_t)(sep - p)) : std::string(p));
        if (!sep) break;
        p = sep + 1;
    }
    for (int i = 0; kBrowsers[i]; i++) {
        for (const auto& dir : dirs) {
            std::string cand = dir + "/" + kBrowsers[i];
            if (::access(cand.c_str(), X_OK) == 0) {
                snprintf(buf, bufsize, "%s", cand.c_str());
                return 1;
            }
        }
    }
    return 0;
}

// Best-effort: if no browser can be found the user is told to open the URL.
void launchBrowser(const std::string& url) {
    char browser[512];
    if (!findBrowser(browser, sizeof(browser))) {
        fprintf(stderr, "\n  No browser found — open %s manually.\n\n", url.c_str());
        return;
    }
    pid_t pid = ::fork();
    if (pid != 0) return;
    ::setsid();
    const char* base = strrchr(browser, '/');
    base = base ? base + 1 : browser;
    if (strstr(base, "chrom") || strstr(base, "brave") || strstr(base, "edge")) {
        std::string appFlag = "--app=" + url;
        ::execlp(browser, base, appFlag.c_str(), "--no-first-run", "--disable-extensions", nullptr);
        ::execlp(browser, base, "--new-window", url.c_str(), nullptr);
    } else if (strstr(base, "firefox")) {
        ::execlp(browser, base, "--new-window", url.c_str(), nullptr);
    } else {
        ::execlp(browser, base, url.c_str(), nullptr);
    }
    ::_exit(127);
}

std::string selfExecutablePath() {
    char buf[4096] = {0};
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    return n > 0 ? std::string(buf, (size_t)n) : std::string();
}

std::string randomToken() {
    u8 raw[32] = {0};
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t got = ::read(fd, raw, sizeof(raw));
        ::close(fd);
        if (got == (ssize_t)sizeof(raw)) return toHex(raw, sizeof(raw));
    }
    // Fall back to something unpredictable enough for a local one-shot token.
    u64 mix = (u64)nowMs() ^ ((u64)::getpid() << 32) ^ (u64)(uintptr_t)&raw;
    return md5Hex(reinterpret_cast<const u8*>(&mix), sizeof(mix));
}

// Launches the elevated instance. Returns false only if the process could not
// be started at all; whether the user completes the authentication is reported
// later, by the new instance claiming the port (or not).
bool spawnElevated(const std::string& method, const std::string& password,
                   const ServerConfig& cfg, std::string* err) {
    std::string exe = selfExecutablePath();
    if (exe.empty()) {
        if (err) *err = "cannot determine this program's own path";
        return false;
    }

    // The token lives in a 0600 file rather than on the command line, so it is
    // not visible to other users through `ps`.
    std::string tokenFile = joinPath(outputRoot(), ".ghost-handover-" + std::to_string(::getpid()));
    int tf = ::open(tokenFile.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (tf < 0) {
        if (err) *err = "cannot create the handover token file in " + outputRoot();
        return false;
    }
    std::string token = randomToken();
    if (::write(tf, token.data(), token.size()) != (ssize_t)token.size()) {
        ::close(tf);
        ::unlink(tokenFile.c_str());
        if (err) *err = "cannot write the handover token";
        return false;
    }
    ::close(tf);
    g_handoverToken = token;
    g_handoverFile  = tokenFile;

    std::string portStr = std::to_string(cfg.port);
    std::vector<std::string> argv;
    if (method == "pkexec") {
        argv = {"pkexec", exe};
    } else if (method == "sudo-nopasswd") {
        argv = {"sudo", "-n", exe};
    } else {
        argv = {"sudo", "-S", "-p", "", exe};
    }
    argv.insert(argv.end(), {"--port", portStr, "--no-browser",
                             "--output", outputRoot(),
                             "--takeover", tokenFile});
    if (cfg.allow_repair_writes) argv.push_back("--allow-writes");
    if (!cfg.web_root.empty()) { argv.push_back("--web"); argv.push_back(cfg.web_root); }
    // The elevated instance must bind the same address. Without this, a parent
    // listening on 0.0.0.0 spawns a child that tries 127.0.0.1, gets
    // EADDRINUSE and dies before the handover completes.
    if (!cfg.bind_address.empty() && cfg.bind_address != "127.0.0.1") {
        argv.push_back("--listen");
        argv.push_back(cfg.bind_address);
    }

    int pw[2] = {-1, -1};
    const bool needsPassword = (method == "sudo-password");
    if (needsPassword) {
        // A pseudo-terminal, not a pipe: sudoers with `requiretty` (Fedora's
        // default) makes `sudo -S` refuse to read a password that does not
        // arrive on a tty. The PTY satisfies isatty(STDIN) and still lets us
        // feed the password directly.
        pw[0] = ::posix_openpt(O_RDWR | O_NOCTTY);
        if (pw[0] < 0) {
            if (err) *err = "cannot allocate a pseudo-terminal for the password";
            return false;
        }
        if (::grantpt(pw[0]) != 0 || ::unlockpt(pw[0]) != 0) {
            ::close(pw[0]);
            if (err) *err = "cannot set up the pseudo-terminal";
            return false;
        }
        // pw[1] is borrowed to carry the slave's name across the fork/exec.
        pw[1] = ::open(::ptsname(pw[0]), O_RDWR | O_NOCTTY);
        if (pw[1] < 0) {
            ::close(pw[0]);
            if (err) *err = "cannot open the pseudo-terminal slave";
            return false;
        }
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        if (err) *err = "fork failed";
        return false;
    }
    if (pid == 0) {
        // Detach so the elevated instance outlives this process.
        ::setsid();
        if (needsPassword) {
            // pw[1] is the slave the parent already opened. sudo -S only
            // needs isatty(STDIN) (the `requiretty` sudoers default), which
            // this dup satisfies; no open() is needed, keeping the fork/exec
            // window free of non-async-signal-safe calls.
            ::dup2(pw[1], STDIN_FILENO);
            ::close(pw[1]);
            ::close(pw[0]);
        } else {
            int devnull = ::open("/dev/null", O_RDONLY);
            if (devnull >= 0) { ::dup2(devnull, STDIN_FILENO); ::close(devnull); }
        }
        // Keep stdout/stderr on a log so authentication failures are diagnosable.
        std::string logPath = joinPath(outputRoot(), "elevated-engine.log");
        int lf = ::open(logPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (lf >= 0) { ::dup2(lf, STDOUT_FILENO); ::dup2(lf, STDERR_FILENO); ::close(lf); }

        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        ::execvp(cargv[0], cargv.data());
        ::_exit(127);
    }

    if (needsPassword) {
        ::close(pw[1]);
        std::string line = password + "\n";
        // The password reaches sudo through this pty master/slave pair on the
        // local host; it is never written to a network socket, and the
        // sudo-password method is refused when the server is reachable
        // remotely (no TLS on the HTTP listener).
        // codeql[cpp/cleartext-transmission]
        ssize_t written = ::write(pw[0], line.data(), line.size());
        (void)written;
        ::close(pw[0]);
    }

    g_elevation.pending = true;
    g_elevation.child_exited = false;
    g_elevation.method = method;
    std::thread([pid]() {
        int status = 0;
        if (::waitpid(pid, &status, 0) == pid) {
            g_elevation.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            g_elevation.child_exited = true;
        }
    }).detach();
    return true;
}

}  // namespace

ElevationMethods detectElevationMethods() {
    ElevationMethods m;
    m.is_root = (::getuid() == 0);
    if (m.is_root) {
        m.preferred = "";
        return m;
    }
    const char* display = ::getenv("DISPLAY");
    const char* wayland = ::getenv("WAYLAND_DISPLAY");
    m.has_display = (display && *display) || (wayland && *wayland);
    m.pkexec = haveExecutable("pkexec") && m.has_display;
    m.sudo   = haveExecutable("sudo");
    m.sudo_nopasswd = m.sudo && sudoWorksWithoutPassword();

    if (m.pkexec)              m.preferred = "pkexec";
    else if (m.sudo_nopasswd)  m.preferred = "sudo-nopasswd";
    else if (m.sudo)           m.preferred = "sudo-password";

    if (!m.pkexec && !m.sudo) {
        m.note = "Neither pkexec nor sudo is installed, so this program cannot raise its own "
                 "privileges. Quit and start it again as root.";
    } else if (!m.pkexec && haveExecutable("pkexec") && !m.has_display) {
        m.note = "pkexec is installed but there is no graphical session for it to show its "
                 "dialog in, so the sudo password is used instead.";
    }
    return m;
}

// When the web server listens on a non-loopback address there is no TLS on
// the HTTP listener, so the sudo-password method must not be offered: the
// password would cross the network in cleartext.  pkexec's system dialog and
// passwordless sudo never send a password through this server.
static ElevationMethods
elevationMethodsForServing(const ElevationMethods& m, bool allowRemote) {
    if (!allowRemote || m.preferred != "sudo-password")
        return m;
    ElevationMethods out = m;
    if (out.pkexec) {
        out.preferred = "pkexec";
        out.note = "Password-based sudo is disabled on remote connections because the web "
                   "server has no TLS; use the graphical authentication instead.";
    } else if (out.sudo_nopasswd) {
        out.preferred = "sudo-nopasswd";
        out.note = "Password-based sudo is disabled on remote connections because the web "
                   "server has no TLS; use passwordless sudo instead.";
    } else {
        out.preferred = "";
        out.note = "Password-based sudo is disabled on remote connections because the web "
                   "server has no TLS. Quit and start this program locally, or as root.";
    }
    return out;
}

bool pathAllowedForServing(const std::string& p) {
    // Files may only be served out of the output root. Without this the API is
    // an unauthenticated arbitrary-file-read on the host.
    if (p.empty()) return false;
    return pathIsWithin(p, outputRoot());
}

// The hex view also takes a raw path so the UI can inspect devices. That path
// may only be a real block device present in sysfs — never an arbitrary host
// file. Images under the output root remain allowed for the job-based view.
bool pathAllowedForRawHex(const std::string& p) {
    if (p.empty()) return false;
    std::string real = realPathOf(p);
    if (real.empty()) return false;
    if (pathIsWithin(real, outputRoot())) return true;
    if (real.rfind("/dev/", 0) != 0) return false;
    struct stat st{};
    if (::stat(real.c_str(), &st) != 0 || !S_ISBLK(st.st_mode)) return false;
    std::string sys = "/sys/block/" + real.substr(5);
    return fileExists(sys + "/size") || fileExists(sys + "/partition");
}

// ---------------------------------------------------------------------------
int startServer(const ServerConfig& cfg) {
    setOutputRoot(cfg.output_root.empty() ? defaultOutputRoot() : cfg.output_root);
    g_allowWrites = cfg.allow_repair_writes;
    makeDirs(outputRoot());
    installShutdownSignals();

    const std::string webRoot = webRootPath(cfg.web_root);

    httplib::Server svr;
    // Without SO_REUSEADDR the privilege handover fails: the old instance's
    // socket lingers in TIME_WAIT for 60 seconds (the browser keeps polling
    // /api/health), and the elevated instance gives up after 15. SO_REUSEPORT
    // alone does not help because it refuses to share a port across different
    // user IDs, and the new process runs as root.
    svr.set_socket_options([](int sock) {
        httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEADDR, 1);
#ifdef SO_REUSEPORT
        httplib::set_socket_opt(sock, SOL_SOCKET, SO_REUSEPORT, 1);
#endif
    });    svr.set_keep_alive_max_count(128);
    svr.set_keep_alive_timeout(30);
    svr.set_read_timeout(120, 0);
    svr.set_write_timeout(600, 0);
    svr.set_payload_max_length(64 * 1024 * 1024);
    svr.set_default_headers({
        {"Access-Control-Allow-Origin", cfg.allow_remote ? "*" : "http://localhost"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"},
        {"X-Content-Type-Options", "nosniff"},
    });
    svr.Options(".*", [](const httplib::Request&, httplib::Response& res) { res.status = 204; });
    // The CORS headers above only stop a malicious page from *reading* the
    // answer; the request still executes. A page from another origin cannot
    // set the Origin header itself, so a mismatching Origin proves the request
    // is cross-site — reject it outright. Plain clients (curl, the engine's
    // own handover IPC) send no Origin header and are unaffected.
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        std::string origin = req.get_header_value("Origin");
        if (!origin.empty()) {
            if (origin != "http://" + req.get_header_value("Host") && origin != "null") {
                res.status = 403;
                res.set_content(errorJson("cross-origin requests are not allowed"),
                                "application/json");
                return httplib::Server::HandlerResponse::Handled;
            }
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    svr.set_exception_handler([](const httplib::Request&, httplib::Response& res,
                                 std::exception_ptr ep) {
        std::string msg = "unhandled error";
        try { if (ep) std::rethrow_exception(ep); }
        catch (const std::exception& e) { msg = e.what(); }
        catch (...) { msg = "unhandled non-std exception"; }
        res.status = 500;
        res.set_content(errorJson(msg), "application/json");
    });

    auto jsonBody = [](const httplib::Request& req) { return json::parse(req.body); };

    // Malformed query parameters fall back to the supplied default instead of
    // being swallowed by an empty catch.
    auto paramInt = [](const httplib::Request& req, const char* name, i64 def) -> i64 {
        const std::string& s = req.get_param_value(name);
        if (s.empty()) return def;
        try { return std::stoll(s); } catch (...) { return def; }
    };

    // ---- meta --------------------------------------------------------------
    svr.Get("/api/health", [&](const httplib::Request&, httplib::Response& res) {
        json::Writer w;
        w.beginObject();
        w.kv("ok", true).kv("status", "online").kv("service", "ghost-recover")
         .kv("version", kVersion).kv("is_root", (bool)(::getuid() == 0))
         .kv("uid", (i64)::getuid()).kv("pid", (i64)::getpid())
         .kv("output_root", outputRoot())
         .kv("writes_allowed", g_allowWrites)
         .kv("web_root", webRoot)
         .kv("carvers", (i64)carverRegistry().size())
         .kv("filesystems", (i64)filesystemRegistry().size());
        ElevationMethods em = elevationMethodsForServing(detectElevationMethods(),
                                                         cfg.allow_remote);
        w.kv("can_elevate", !em.preferred.empty()).kv("elevate_method", em.preferred);
        w.endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- privileges --------------------------------------------------------
    svr.Get("/api/privileges", [&](const httplib::Request&, httplib::Response& res) {
        ElevationMethods m = elevationMethodsForServing(detectElevationMethods(),
                                                        cfg.allow_remote);
        json::Writer w;
        w.beginObject();
        w.kv("ok", true).kv("is_root", m.is_root).kv("uid", (i64)::getuid());
        w.kv("pkexec", m.pkexec).kv("sudo", m.sudo).kv("sudo_nopasswd", m.sudo_nopasswd);
        w.kv("has_display", m.has_display).kv("preferred", m.preferred).kv("note", m.note);
        // Which disks are actually blocked by the lack of privileges.
        i64 blocked = 0;
        for (const auto& d : detectDisks()) if (!d.accessible) blocked++;
        w.kv("inaccessible_disks", blocked);
        w.endObject();
        res.set_content(w.str(), "application/json");
    });

    svr.Post("/api/elevate", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        if (::getuid() == 0) {
            json::Writer w;
            w.beginObject().kv("ok", true).kv("already_root", true)
             .kv("message", "already running with full disk access").endObject();
            res.set_content(w.str(), "application/json");
            return;
        }
        // One elevation at a time: a second request would spawn a second
        // sudo/pkexec dialog and burn the one-time handover token, leaving
        // the first child unable to claim the port.
        if (g_elevation.pending.load() && !g_elevation.child_exited.load()) {
            res.set_content(errorJson("an elevation is already in progress — finish or dismiss "
                                      "the open authentication dialog first"),
                            "application/json");
            return;
        }
        if (g_handedOver.load()) {
            res.set_content(errorJson("this session already handed its port over — reload the page"),
                            "application/json");
            return;
        }
        ElevationMethods m = elevationMethodsForServing(detectElevationMethods(),
                                                        cfg.allow_remote);
        std::string method = body.getStr("method", m.preferred);
        if (method.empty()) {
            res.set_content(errorJson(
                m.note.empty() ? "no way to raise privileges on this system" : m.note,
                "Quit and run: sudo ghost_recover"), "application/json");
            return;
        }
        if (method == "sudo-password" && cfg.allow_remote) {
            res.set_content(errorJson(
                "password-based sudo is disabled when the web server is reachable from other "
                "machines (--listen 0.0.0.0): the password would be sent over unencrypted HTTP. "
                "Open the interface on this computer (http://localhost) instead, or use the "
                "graphical authentication or passwordless-sudo methods."),
                "application/json");
            return;
        }
        if (method == "pkexec" && !m.pkexec) {
            res.set_content(errorJson("pkexec is not usable here",
                                      m.note.empty() ? "no graphical session" : m.note),
                            "application/json");
            return;
        }
        if ((method == "sudo-password" || method == "sudo-nopasswd") && !m.sudo) {
            res.set_content(errorJson("sudo is not installed"), "application/json");
            return;
        }
        std::string password = body.getStr("password");
        if (method == "sudo-password" && password.empty()) {
            res.set_content(errorJson("a password is required for this method"),
                            "application/json");
            return;
        }

        std::string err;
        if (!spawnElevated(method, password, cfg, &err)) {
            res.set_content(errorJson(err), "application/json");
            return;
        }
        json::Writer w;
        w.beginObject();
        w.kv("ok", true).kv("method", method);
        w.kv("message", method == "pkexec"
                 ? "Complete the authentication in the system dialog. This page will reconnect "
                   "automatically once the engine restarts with full disk access."
                 : "Starting the engine with full disk access. This page will reconnect "
                   "automatically.");
        w.endObject();
        res.set_content(w.str(), "application/json");
    });

    svr.Get("/api/elevate/status", [](const httplib::Request&, httplib::Response& res) {
        json::Writer w;
        w.beginObject().kv("ok", true);
        w.kv("is_root", (bool)(::getuid() == 0));
        w.kv("pending", g_elevation.pending.load());
        w.kv("handed_over", g_handedOver.load());
        const bool failed = g_elevation.pending.load() && g_elevation.child_exited.load() &&
                            !g_handedOver.load();
        w.kv("failed", failed);
        w.kv("exit_code", (i64)g_elevation.exit_code.load());
        if (failed) {
            int code = g_elevation.exit_code.load();
            std::string detail;
            if (g_elevation.method == "pkexec") {
                detail = (code == 126) ? "Authentication was dismissed or refused."
                       : (code == 127) ? "pkexec could not run this program."
                                       : "The authentication dialog did not complete.";
            } else {
                detail = (code == 1) ? "The password was not accepted."
                       : (code == 127) ? "sudo could not run this program."
                                       : "sudo exited with code " + std::to_string(code) + ".";
            }
            // Surface whatever sudo/pkexec printed, which is usually the reason.
            std::ifstream lf(joinPath(outputRoot(), "elevated-engine.log"));
            std::string line, tail;
            while (std::getline(lf, line)) {
                line = trim(line);
                if (!line.empty()) tail = line;
            }
            if (!tail.empty()) detail += " (" + tail + ")";
            w.kv("detail", detail);
        }
        w.endObject();
        res.set_content(w.str(), "application/json");
    });

    // Called by the elevated instance once it is running as root, to claim the
    // port. Authenticated by a one-time token that only this process and root
    // can read.
    svr.Post("/api/handover", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        std::string token = body.getStr("token");
        bool valid = !g_handoverToken.empty() && token.size() == g_handoverToken.size();
        if (valid) {
            // Constant-time compare; the token is short-lived but there is no
            // reason to leak it a byte at a time.
            unsigned diff = 0;
            for (size_t i = 0; i < token.size(); i++)
                diff |= (unsigned)(token[i] ^ g_handoverToken[i]);
            valid = (diff == 0);
        }
        if (!valid) {
            res.status = 403;
            res.set_content(errorJson("invalid handover token"), "application/json");
            return;
        }
        g_handedOver = true;
        g_handoverToken.clear();        // one-time: never honour a second claim
        if (!g_handoverFile.empty()) ::unlink(g_handoverFile.c_str());
        json::Writer w;
        w.beginObject().kv("ok", true).kv("message", "standing down").endObject();
        res.set_content(w.str(), "application/json");
        // Let the response flush before the listener closes.
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            if (g_server) g_server->stop();
        }).detach();
    });

    // Explicit engine shutdown — the UI's "Shut down" button, equivalent to a
    // SIGTERM. The engine exits once the response flushes, so a later start
    // always finds the port free.
    svr.Post("/api/shutdown", [](const httplib::Request&, httplib::Response& res) {
        json::Writer w;
        w.beginObject().kv("ok", true).kv("message", "shutting down").endObject();
        res.set_content(w.str(), "application/json");
        std::thread([]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            requestEngineShutdown();
        }).detach();
    });

    svr.Get("/api/filesystems", [](const httplib::Request&, httplib::Response& res) {
        auto reg = filesystemRegistry();
        json::Writer w;
        w.beginObject().kv("ok", true).kv("count", (i64)reg.size()).key("filesystems").beginArray();
        for (const auto& f : reg) {
            w.beginObject().kv("id", f.id).kv("name", f.name).kv("family", f.family)
             .kv("category", f.category).kv("magic", f.magic).kv("readonly", f.readonly)
             .kv("supported", f.supported).endObject();
        }
        w.endArray().endObject();
        res.set_content(w.str(), "application/json");
    });

    svr.Get("/api/carvers", [](const httplib::Request&, httplib::Response& res) {
        const auto& reg = carverRegistry();
        json::Writer w;
        w.beginObject().kv("ok", true).kv("count", (i64)reg.size());
        w.key("categories").beginArray();
        for (const auto& c : carverCategories()) w.value(c);
        w.endArray();
        w.key("carvers").beginArray();
        for (const auto& c : reg) {
            w.beginObject().kv("name", c.name).kv("ext", c.ext).kv("category", c.category)
             .kv("max_size", c.max_size).kv("validated", c.validator != nullptr)
             .kv("magic_hex", toHex(c.magic.data(), c.magic.size())).endObject();
        }
        w.endArray().endObject();
        res.set_content(w.str(), "application/json");
    });

    svr.Get("/api/disks", [](const httplib::Request&, httplib::Response& res) {
        auto disks = detectDisks();
        json::Writer w;
        w.beginObject().kv("ok", true).kv("count", (i64)disks.size()).key("disks").beginArray();
        for (const auto& d : disks) {
            w.beginObject();
            w.kv("name", d.name).kv("display_name", d.display_name).kv("device_path", d.device_path)
             .kv("type", d.type).kv("type_label", d.type_label)
             .kv("size_bytes", d.size_bytes).kv("size_human", humanSize(d.size_bytes))
             .kv("removable", d.removable).kv("rotational", d.rotational)
             .kv("accessible", d.accessible).kv("status_message", d.status_message)
             .kv("vendor", d.vendor).kv("model", d.model).kv("serial", d.serial)
             .kv("partition_count", d.partition_count).kv("raid_member", d.is_raid_member)
             .kv("logical_sector", d.logical_sector).kv("physical_sector", d.physical_sector);
            w.endObject();
        }
        w.endArray().endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- file browser ------------------------------------------------------
    svr.Get("/api/browse", [](const httplib::Request& req, httplib::Response& res) {
        std::string path = req.get_param_value("path");
        if (path.empty() || path == "~") {
            const char* home = ::getenv("HOME");
            path = home ? home : "/";
        }
        std::string real = realPathOf(path);
        if (real.empty()) {
            res.status = 404;
            res.set_content(errorJson("directory not found: " + path), "application/json");
            return;
        }
        DIR* dir = opendir(real.c_str());
        if (!dir) {
            res.status = 403;
            res.set_content(errorJson("cannot read directory: " + real), "application/json");
            return;
        }
        struct Entry { std::string name; bool isDir; i64 size; };
        std::vector<Entry> dirs, files;
        struct dirent* e;
        while ((e = readdir(dir)) != nullptr) {
            std::string n = e->d_name;
            if (n == "." || n == "..") continue;
            std::string full = joinPath(real, n);
            struct stat st{};
            bool isDir = false;
            i64 size = 0;
            if (::stat(full.c_str(), &st) == 0) {
                isDir = S_ISDIR(st.st_mode);
                size = (i64)st.st_size;
            } else {
                isDir = (e->d_type == DT_DIR);
            }
            (isDir ? dirs : files).push_back({n, isDir, size});
        }
        closedir(dir);
        auto byName = [](const Entry& a, const Entry& b) { return a.name < b.name; };
        std::sort(dirs.begin(), dirs.end(), byName);
        std::sort(files.begin(), files.end(), byName);

        json::Writer w;
        w.beginObject().kv("ok", true).kv("path", real).kv("parent", dirName(real));
        w.key("entries").beginArray();
        if (real != "/") w.beginObject().kv("name", "..").kv("is_dir", true).kv("size", (i64)0).endObject();
        for (const auto& d : dirs)
            w.beginObject().kv("name", d.name).kv("is_dir", true).kv("size", (i64)0).endObject();
        for (const auto& f : files)
            w.beginObject().kv("name", f.name).kv("is_dir", false).kv("size", f.size)
             .kv("size_human", humanSize(f.size)).endObject();
        w.endArray().endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- detect ------------------------------------------------------------
    svr.Post("/api/detect", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = jsonBody(req);
        Target t = readTarget(body);
        std::string err;
        auto disk = openTarget(t.path, t.offset, t.length, &err);
        if (!disk) {
            res.set_content(errorJson(err), "application/json");
            return;
        }
        DetectResult d = detectFilesystem(*disk);
        json::Writer w;
        w.beginObject().kv("ok", true).key("result").beginObject();
        w.kv("detected", d.detected).kv("filesystem", d.filesystem).kv("family", d.family)
         .kv("label", d.label).kv("uuid", d.uuid)
         .kv("size_bytes", d.size_bytes).kv("size_human", humanSize(d.size_bytes))
         .kv("block_size", d.block_size).kv("confidence", d.confidence)
         .kv("is_container", d.is_container).kv("container", d.container)
         .kv("note", d.note).kv("error", d.error)
         .kv("sector_size", disk->sectorSize())
         .kv("raw_device", disk->isRawDevice());
        w.key("repairs").beginArray();
        for (const auto& a : availableRepairs(d.filesystem)) w.value(a);
        w.endArray();
        w.endObject().endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- partitions ---------------------------------------------------------
    svr.Post("/api/partitions", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = jsonBody(req);
        Target t = readTarget(body);
        std::string err;
        auto disk = openTarget(t.path, 0, 0, &err);
        if (!disk) {
            res.set_content(errorJson(err), "application/json");
            return;
        }
        PartitionOptions opt;
        opt.detect_filesystems = body.getBool("detect_filesystems", true);
        opt.find_deleted = body.getBool("find_deleted", false);
        opt.deleted_scan_limit = body.getInt("deleted_scan_limit", 0);

        Progress prog;
        auto pr = scanPartitions(*disk, opt, prog);

        json::Writer w;
        w.beginObject().kv("ok", true).key("result").beginObject();
        w.kv("ok", pr.ok).kv("partition_table", pr.partition_table).kv("error", pr.error)
         .kv("count", pr.count).kv("deleted_count", pr.deleted_count)
         .kv("image_size", pr.image_size).kv("image_size_human", humanSize(pr.image_size))
         .kv("sector_size", pr.sector_size).kv("total_sectors", pr.total_sectors)
         .kv("disk_guid", pr.disk_guid).kv("disk_type", pr.disk_type)
         .kv("gpt_primary_ok", pr.gpt_primary_ok).kv("gpt_backup_ok", pr.gpt_backup_ok)
         .kv("mbr_ok", pr.mbr_ok);
        w.key("warnings").beginArray();
        for (const auto& s : pr.warnings) w.value(s);
        w.endArray();
        w.key("partitions").beginArray();
        for (const auto& p : pr.partitions) writePartition(w, p);
        w.endArray();
        w.key("deleted_partitions").beginArray();
        for (const auto& p : pr.deleted_partitions) writePartition(w, p);
        w.endArray();
        w.endObject().endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- jobs: scan / carve / deep -----------------------------------------
    auto startScanJob = [&](const json::Value& body, bool withCarve, bool withScan)
        -> std::pair<std::string, std::string> {
        Target t = readTarget(body);
        std::string err;
        {
            auto probe = openTarget(t.path, t.offset, t.length, &err);
            if (!probe) return {"", err};
        }
        ScanOptions sopt = readScanOptions(body);
        std::string defaultOut = joinPath(outputRoot(), "carved");
        CarveOptions copt = readCarveOptions(body, defaultOut);
        bool unallocOnly = copt.skip_allocated;

        std::string kind = withScan && withCarve ? "deep" : (withCarve ? "carve" : "scan");
        std::string id = JobManager::instance().submit(kind, t.path,
            [t, sopt, copt, withCarve, withScan, unallocOnly](Job& job) -> std::string {
                auto stored = std::make_shared<StoredResult>();
                stored->kind = job.kind;
                stored->target = t.path;
                stored->offset = t.offset;
                stored->length = t.length;

                std::string openErr;
                auto disk = openTarget(t.path, t.offset, t.length, &openErr);
                if (!disk) throw std::runtime_error(openErr);

                if (withScan) {
                    job.progress.setPhase("scanning filesystem");
                    stored->scan = scanVolume(*disk, t.filesystem, sopt, job.progress);
                    stored->filesystem = stored->scan.filesystem;
                    stored->files = stored->scan.files;
                }

                if (withCarve && !job.progress.cancelled()) {
                    CarveOptions co = copt;
                    if (unallocOnly) {
                        job.progress.setPhase("mapping free space");
                        co.regions = unallocatedRegions(*disk, stored->filesystem, job.progress);
                    }
                    job.progress.setPhase("carving");
                    stored->carve = carveDevice(*disk, co, job.progress);
                    size_t base = stored->files.size();
                    for (size_t i = 0; i < stored->carve.files.size(); i++) {
                        // Skip carved results that duplicate a file the
                        // filesystem scan already recovered at the same place.
                        const auto& cf = stored->carve.files[i];
                        bool dup = false;
                        for (const auto& sf : stored->scan.files) {
                            if (sf.extents.empty()) continue;
                            if (std::llabs(sf.extents.front().offset - cf.offset) < 4096) {
                                dup = true;
                                break;
                            }
                        }
                        if (dup) continue;
                        stored->files.push_back(carvedToRecovered(cf, base + i));
                    }
                }

                ResultStore::instance().put(job.id, stored);

                json::Writer w;
                w.beginObject();
                w.kv("ok", true).kv("job", job.id).kv("kind", job.kind);
                w.kv("file_count", (i64)stored->files.size());
                if (withScan) writeScanSummary(w, stored->scan);
                if (withCarve) writeCarveSummary(w, stored->carve);
                w.endObject();
                return w.str();
            });
        return {id, ""};
    };

    auto jobEndpoint = [&](bool withCarve, bool withScan) {
        return [&, withCarve, withScan](const httplib::Request& req, httplib::Response& res) {
            auto body = json::parse(req.body);
            auto [id, err] = startScanJob(body, withCarve, withScan);
            if (id.empty()) {
                res.set_content(errorJson(err.empty() ? "could not start job" : err),
                                "application/json");
                return;
            }
            json::Writer w;
            w.beginObject().kv("ok", true).kv("job", id).endObject();
            res.set_content(w.str(), "application/json");
        };
    };

    svr.Post("/api/scan",  jobEndpoint(false, true));
    svr.Post("/api/carve", jobEndpoint(true, false));
    svr.Post("/api/deep",  jobEndpoint(true, true));

    // ---- job status ---------------------------------------------------------
    auto writeJob = [](json::Writer& w, const std::shared_ptr<Job>& j) {
        w.beginObject();
        w.kv("id", j->id).kv("kind", j->kind).kv("target", j->target);
        w.kv("state", jobStateName(j->state.load()));
        w.kv("phase", j->progress.phase());
        w.kv("percent", j->progress.percent());
        w.kv("done", j->progress.done());
        w.kv("total", j->progress.total());
        w.kv("found", j->progress.found());
        w.kv("created_ms", j->created_ms);
        w.kv("started_ms", j->started_ms);
        w.kv("finished_ms", j->finished_ms);
        std::string e = j->errorText();
        if (!e.empty()) w.kv("error", e);
        w.endObject();
    };

    svr.Get("/api/jobs", [&](const httplib::Request&, httplib::Response& res) {
        JobManager::instance().prune();
        auto jobs = JobManager::instance().list();
        json::Writer w;
        w.beginObject().kv("ok", true).key("jobs").beginArray();
        for (const auto& j : jobs) writeJob(w, j);
        w.endArray().endObject();
        res.set_content(w.str(), "application/json");
    });

    svr.Get("/api/job", [&](const httplib::Request& req, httplib::Response& res) {
        auto j = JobManager::instance().get(req.get_param_value("id"));
        if (!j) {
            res.status = 404;
            res.set_content(errorJson("no such job"), "application/json");
            return;
        }
        json::Writer w;
        w.beginObject().kv("ok", true).key("job");
        writeJob(w, j);
        if (j->state.load() == JobState::Done) {
            std::string r = j->resultJson();
            if (!r.empty()) w.key("result").raw(r);
        }
        w.endObject();
        res.set_content(w.str(), "application/json");
    });

    svr.Post("/api/job/cancel", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        std::string id = body.getStr("id");
        bool ok = JobManager::instance().cancel(id);
        json::Writer w;
        w.beginObject().kv("ok", ok);
        if (!ok) w.kv("error", "job not found or already finished");
        w.endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- paged results ------------------------------------------------------
    svr.Get("/api/results", [&](const httplib::Request& req, httplib::Response& res) {
        auto stored = ResultStore::instance().get(req.get_param_value("job"));
        if (!stored) {
            res.status = 404;
            res.set_content(errorJson("no results for that job (it may have been pruned)"),
                            "application/json");
            return;
        }
        i64 offset = 0, limit = 200;
        offset = paramInt(req, "offset", offset);
        limit  = paramInt(req, "limit", limit);
        if (offset < 0) offset = 0;                     // negative pages would read OOB
        if (limit < 1) limit = 1;
        if (limit > 5000) limit = 5000;
        std::string q = toLower(req.get_param_value("q"));
        std::string ext = toLower(req.get_param_value("ext"));
        std::string only = req.get_param_value("only");     // "deleted" | "live" | ""
        std::string sort = req.get_param_value("sort");     // name|size|mtime|confidence

        std::vector<size_t> idx;
        idx.reserve(stored->files.size());
        for (size_t i = 0; i < stored->files.size(); i++) {
            const auto& f = stored->files[i];
            if (only == "deleted" && !f.is_deleted) continue;
            if (only == "live" && f.is_deleted) continue;
            if (!ext.empty() && extensionOf(f.name) != ext) continue;
            if (!q.empty()) {
                std::string hay = toLower(f.path.empty() ? f.name : f.path);
                if (hay.find(q) == std::string::npos) continue;
            }
            idx.push_back(i);
        }
        if (!sort.empty()) {
            const auto& files = stored->files;
            std::stable_sort(idx.begin(), idx.end(), [&](size_t a, size_t b) {
                if (sort == "size") return files[a].size > files[b].size;
                if (sort == "mtime") return files[a].mtime > files[b].mtime;
                if (sort == "confidence") return files[a].confidence > files[b].confidence;
                return files[a].path < files[b].path;
            });
        }

        json::Writer w;
        w.beginObject().kv("ok", true).kv("job", req.get_param_value("job"));
        w.kv("total", (i64)stored->files.size()).kv("matched", (i64)idx.size());
        w.kv("offset", offset).kv("limit", limit);
        w.key("files").beginArray();
        for (i64 i = offset; i < (i64)idx.size() && i < offset + limit; i++)
            writeFile(w, stored->files[idx[(size_t)i]], idx[(size_t)i]);
        w.endArray();
        // Extension histogram so the UI can build its filter without a second pass.
        std::map<std::string, i64> byExt;
        for (const auto& f : stored->files) byExt[extensionOf(f.name)]++;
        w.key("by_ext").beginObject();
        for (const auto& [k, v] : byExt) w.kv(k.empty() ? "(none)" : k, v);
        w.endObject();
        w.endObject();
        res.set_content(w.str(), "application/json");
    });

    // Full detail for one file, including where its data physically lives.
    svr.Get("/api/fileinfo", [&](const httplib::Request& req, httplib::Response& res) {
        auto stored = ResultStore::instance().get(req.get_param_value("job"));
        i64 index = paramInt(req, "index", -1);
        if (!stored || index < 0 || index >= (i64)stored->files.size()) {
            res.status = 404;
            res.set_content(errorJson("no such file in that job"), "application/json");
            return;
        }
        const RecoveredFile& f = stored->files[(size_t)index];
        json::Writer w;
        w.beginObject().kv("ok", true).key("file");
        writeFile(w, f, (size_t)index);
        w.key("detail").beginObject();
        w.kv("alloc_size", f.alloc_size).kv("uid", (i64)f.uid).kv("gid", (i64)f.gid)
         .kv("mode", (i64)f.mode).kv("nlink", (i64)f.nlink)
         .kv("atime_iso", isoTime(f.atime)).kv("ctime_iso", isoTime(f.ctime))
         .kv("crtime_iso", isoTime(f.crtime)).kv("dtime_iso", isoTime(f.dtime))
         .kv("codec", f.codec).kv("parent_id", (i64)f.parent_id)
         .kv("extent_count", (i64)f.extents.size());
        w.key("extents").beginArray();
        for (size_t i = 0; i < f.extents.size() && i < 256; i++) {
            w.beginObject().kv("offset", f.extents[i].offset)
             .kv("length", f.extents[i].length).kv("sparse", f.extents[i].sparse).endObject();
        }
        w.endArray();
        w.endObject().endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- file content -------------------------------------------------------
    // Serves the bytes of one recovered file straight from the device.
    svr.Get("/api/content", [&](const httplib::Request& req, httplib::Response& res) {
        auto stored = ResultStore::instance().get(req.get_param_value("job"));
        if (!stored) {
            res.status = 404;
            res.set_content(errorJson("no results for that job"), "application/json");
            return;
        }
        i64 index = paramInt(req, "index", -1);
        if (index < 0 || index >= (i64)stored->files.size()) {
            res.status = 404;
            res.set_content(errorJson("index out of range"), "application/json");
            return;
        }
        i64 maxBytes = 64LL * 1024 * 1024;
        // A missing/negative "max" must not turn into an unbounded read.
        i64 m = paramInt(req, "max", 0);
        if (m > 0) maxBytes = std::min<i64>(maxBytes, m);

        const RecoveredFile& f = stored->files[(size_t)index];
        std::string err;
        auto disk = openTarget(stored->target, stored->offset, stored->length, &err);
        if (!disk) {
            res.status = 500;
            res.set_content(errorJson(err), "application/json");
            return;
        }
        auto data = readFileData(*disk, f, maxBytes);
        if (data.empty()) {
            res.status = 404;
            res.set_content(errorJson("no readable data for this file"), "application/json");
            return;
        }
        std::string mime = mimeForExtension(extensionOf(f.name));
        res.set_header("Content-Disposition",
                       "inline; filename=\"" + sanitizeFilename(f.name) + "\"");
        res.set_content(std::string(data.begin(), data.end()), mime.c_str());
    });

    // Hex view of a range, either of a stored file or of the raw device.
    svr.Get("/api/hex", [&](const httplib::Request& req, httplib::Response& res) {
        i64 offset = 0, length = 512;
        offset = paramInt(req, "offset", offset);
        length = paramInt(req, "length", length);
        if (offset < 0) offset = 0;             // negative offsets read out of bounds
        if (length < 16) length = 16;
        if (length > 65536) length = 65536;

        std::vector<u8> data;
        i64 total = 0;
        std::string sourceLabel;

        std::string jobId = req.get_param_value("job");
        if (!jobId.empty()) {
            auto stored = ResultStore::instance().get(jobId);
            i64 index = paramInt(req, "index", -1);
            if (!stored || index < 0 || index >= (i64)stored->files.size()) {
                res.status = 404;
                res.set_content(errorJson("no such file in that job"), "application/json");
                return;
            }
            std::string err;
            auto disk = openTarget(stored->target, stored->offset, stored->length, &err);
            if (!disk) {
                res.status = 500;
                res.set_content(errorJson(err), "application/json");
                return;
            }
            const RecoveredFile& f = stored->files[(size_t)index];
            // Bound the read to the file's real length. An offset near INT64_MAX
            // would otherwise make offset+length overflow and force readFileData
            // into materialising the whole file to return nothing at all.
            i64 fileLen = f.size > 0 ? f.size : 0;
            if (fileLen <= 0)
                for (const auto& e : f.extents) fileLen += std::max<i64>(0, e.length);
            i64 end = offset + length;
            if (end < offset || (fileLen > 0 && offset >= fileLen)) {
                res.status = 404;
                res.set_content(errorJson("offset is beyond the end of the file"),
                                "application/json");
                return;
            }
            if (fileLen > 0) end = std::min(end, fileLen);
            auto all = readFileData(*disk, f, end);
            total = f.size > 0 ? f.size : (i64)all.size();
            if (offset < (i64)all.size())
                data.assign(all.begin() + offset, all.begin() + std::min<size_t>(all.size(), (size_t)(offset + length)));
            sourceLabel = f.path.empty() ? f.name : f.path;
        } else {
            std::string path = req.get_param_value("path");
            if (path.empty()) {
                res.set_content(errorJson("provide either job+index or path"), "application/json");
                return;
            }
            if (!pathAllowedForRawHex(path)) {
                res.status = 403;
                res.set_content(errorJson("raw hex view is limited to block devices and files "
                                          "under " + outputRoot()), "application/json");
                return;
            }
            std::string err;
            auto disk = openTarget(path, 0, 0, &err);
            if (!disk) {
                res.status = 404;
                res.set_content(errorJson(err), "application/json");
                return;
            }
            total = disk->size();
            if (total > 0 && offset >= total) {
                res.status = 404;
                res.set_content(errorJson("offset is beyond the end of the device"),
                                "application/json");
                return;
            }
            data = disk->readBlock((u64)offset, length);
            sourceLabel = path;
        }

        json::Writer w;
        w.beginObject().kv("ok", true).kv("source", sourceLabel).kv("offset", offset)
         .kv("length", (i64)data.size()).kv("total_size", total);
        w.key("lines").beginArray();
        for (size_t i = 0; i < data.size(); i += 16) {
            size_t end = std::min(i + 16, data.size());
            std::string hex, ascii;
            for (size_t j = i; j < end; j++) {
                char b[4];
                snprintf(b, sizeof(b), "%02X ", data[j]);
                hex += b;
                ascii += (data[j] >= 32 && data[j] < 127) ? (char)data[j] : '.';
            }
            while (hex.size() < 48) hex += ' ';
            w.beginObject().kv("offset", offset + (i64)i).kv("hex", hex).kv("ascii", ascii).endObject();
        }
        w.endArray().endObject();
        res.set_content(w.str(), "application/json");
    });

    // Serves a file already written under the output root (carved results).
    svr.Get("/api/file", [&](const httplib::Request& req, httplib::Response& res) {
        std::string path = req.get_param_value("path");
        if (!pathAllowedForServing(path)) {
            res.status = 403;
            res.set_content(errorJson("path is outside the output directory",
                                      "only files under " + outputRoot() + " can be served"),
                            "application/json");
            return;
        }
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            res.status = 404;
            res.set_content(errorJson("file not found"), "application/json");
            return;
        }
        // Recovered files can be gigabytes; slurping one into memory and
        // base64-encoding it would exhaust the HTTP handler. Serve at most the
        // first few megabytes — enough for a preview — and say so in a header.
        constexpr i64 kPreviewCap = 4 * 1024 * 1024;
        f.seekg(0, std::ios::end);
        i64 size = (i64)f.tellg();
        f.seekg(0, std::ios::beg);
        i64 take = std::min<i64>(size, kPreviewCap);
        std::string data((size_t)take, '\0');
        if (take > 0) f.read(&data[0], take);
        res.set_header("X-File-Size", std::to_string(size));
        if (size > take) res.set_header("X-Content-Truncated", "1");
        res.set_header("Content-Disposition",
                       "inline; filename=\"" + sanitizeFilename(baseName(path)) + "\"");
        res.set_content(data, mimeForExtension(extensionOf(path)).c_str());
    });

    // ---- extraction ---------------------------------------------------------
    svr.Post("/api/extract", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        std::string jobId = body.getStr("job");
        auto stored = ResultStore::instance().get(jobId);
        if (!stored) {
            res.set_content(errorJson("no results for that job"), "application/json");
            return;
        }
        ExtractOptions opt;
        opt.output_dir     = body.getStr("output_dir", joinPath(outputRoot(), "recovered"));
        opt.preserve_paths = body.getBool("preserve_paths", true);
        opt.preserve_times = body.getBool("preserve_times", true);
        opt.write_manifest = body.getBool("write_manifest", true);
        opt.compute_hashes = body.getBool("compute_hashes", true);
        opt.overwrite      = body.getBool("overwrite", false);

        std::vector<size_t> indices;
        if (const json::Value* arr = body.getArray("indices"))
            for (const auto& v : arr->arr) {
                i64 i = v.asInt();
                if (i >= 0 && i < (i64)stored->files.size()) indices.push_back((size_t)i);
            }

        std::string id = JobManager::instance().submit("extract", stored->target,
            [stored, opt, indices](Job& job) -> std::string {
                std::string err;
                auto disk = openTarget(stored->target, stored->offset, stored->length, &err);
                if (!disk) throw std::runtime_error(err);
                std::vector<RecoveredFile> selection;
                if (indices.empty()) selection = stored->files;
                else for (size_t i : indices) selection.push_back(stored->files[i]);

                ExtractResult r = extractFiles(*disk, selection, opt, job.progress);
                json::Writer w;
                w.beginObject();
                w.kv("ok", r.ok).kv("output_dir", r.output_dir)
                 .kv("files_written", (i64)r.files_written)
                 .kv("files_failed", (i64)r.files_failed)
                 .kv("files_undecoded", (i64)r.files_undecoded)
                 .kv("bytes_written", r.bytes_written)
                 .kv("bytes_human", humanSize(r.bytes_written));
                if (!r.error.empty()) w.kv("error", r.error);
                w.key("failures").beginArray();
                for (size_t i = 0; i < r.failures.size() && i < 200; i++) w.value(r.failures[i]);
                w.endArray();
                w.key("undecoded").beginArray();
                for (size_t i = 0; i < r.undecoded.size() && i < 200; i++) w.value(r.undecoded[i]);
                w.endArray();
                w.endObject();
                return w.str();
            });

        json::Writer w;
        w.beginObject().kv("ok", true).kv("job", id).endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- imaging ------------------------------------------------------------
    svr.Post("/api/image", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        Target t = readTarget(body);
        ImageOptions opt;
        opt.output_path = body.getStr("output_path",
                                      joinPath(outputRoot(), "images/clone.img"));
        opt.mapfile     = body.getStr("mapfile", opt.output_path + ".map");
        opt.block_size  = body.getInt("block_size", 1 << 20);
        opt.retry_passes = body.getInt("retry_passes", 2);
        opt.sparse      = body.getBool("sparse", true);
        opt.verify      = body.getBool("verify", false);
        opt.start       = t.offset;
        opt.length      = t.length;

        std::string err;
        { auto probe = openTarget(t.path, 0, 0, &err); if (!probe) {
            res.set_content(errorJson(err), "application/json");
            return; } }

        std::string id = JobManager::instance().submit("image", t.path,
            [t, opt](Job& job) -> std::string {
                std::string err2;
                auto disk = openTarget(t.path, 0, 0, &err2);
                if (!disk) throw std::runtime_error(err2);
                ImageResult r = createImage(*disk, opt, job.progress);
                json::Writer w;
                w.beginObject();
                w.kv("ok", r.ok).kv("output_path", r.output_path)
                 .kv("bytes_copied", r.bytes_copied).kv("bytes_bad", r.bytes_bad)
                 .kv("bad_regions", r.bad_regions).kv("elapsed_ms", r.elapsed_ms)
                 .kv("rate_mb_s", r.rate_mb_s).kv("md5", r.md5);
                if (!r.error.empty()) w.kv("error", r.error);
                w.key("bad_map").beginArray();
                for (size_t i = 0; i < r.bad_map.size() && i < 500; i++)
                    w.beginObject().kv("offset", r.bad_map[i].offset)
                     .kv("length", r.bad_map[i].length).endObject();
                w.endArray();
                w.endObject();
                return w.str();
            });
        json::Writer w;
        w.beginObject().kv("ok", true).kv("job", id).endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- RAID ---------------------------------------------------------------
    svr.Post("/api/raid/detect", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        std::vector<std::string> members;
        if (const json::Value* arr = body.getArray("members"))
            for (const auto& v : arr->arr) members.push_back(v.asStr());
        if (members.size() < 2) {
            res.set_content(errorJson("supply at least two member devices or images"),
                            "application/json");
            return;
        }
        Progress prog;
        RaidLayout layout = detectRaidLayout(members, prog);
        json::Writer w;
        w.beginObject().kv("ok", true).key("layout").beginObject();
        w.kv("level", raidLevelName(layout.level)).kv("chunk_size", layout.chunk_size)
         .kv("members", layout.members).kv("parity_layout", layout.parity_layout)
         .kv("confidence", layout.confidence).kv("detected_from", layout.detected_from)
         .kv("ambiguous", layout.ambiguous);
        w.key("alternatives").beginArray();
        for (const auto& a : layout.alternatives) w.value(a);
        w.endArray();
        w.key("disks").beginArray();
        for (const auto& d : layout.disks) {
            w.beginObject().kv("path", d.path).kv("role", d.role)
             .kv("data_offset", d.data_offset).kv("size", d.size)
             .kv("present", d.present).kv("uuid", d.uuid).endObject();
        }
        w.endArray();
        w.key("notes").beginArray();
        for (const auto& n : layout.notes) w.value(n);
        w.endArray();
        w.endObject().endObject();
        res.set_content(w.str(), "application/json");
    });

    svr.Post("/api/raid/assemble", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        RaidLayout layout;
        layout.level = raidLevelFromString(body.getStr("level"));
        layout.chunk_size = body.getInt("chunk_size", 65536);
        layout.parity_layout = body.getStr("parity_layout", "left-symmetric");
        if (const json::Value* arr = body.getArray("members")) {
            for (const auto& v : arr->arr) {
                RaidMember m;
                if (v.isObject()) {
                    m.path = v.getStr("path");
                    m.data_offset = v.getInt("data_offset", 0);
                    m.size = v.getInt("size", 0);
                    m.present = v.getBool("present", true);
                } else {
                    m.path = v.asStr();
                }
                layout.disks.push_back(std::move(m));
            }
        }
        layout.members = (int)layout.disks.size();
        if (layout.level == RaidLevel::Unknown || layout.disks.empty()) {
            res.set_content(errorJson("level and members are required"), "application/json");
            return;
        }
        std::string outPath = body.getStr("output_path", joinPath(outputRoot(), "raid/array.img"));
        i64 maxBytes = body.getInt("max_bytes", 0);

        std::string id = JobManager::instance().submit("raid", outPath,
            [layout, outPath, maxBytes](Job& job) -> std::string {
                RaidBuildResult r = assembleRaid(layout, outPath, maxBytes, job.progress);
                json::Writer w;
                w.beginObject();
                w.kv("ok", r.ok).kv("output_path", r.output_path)
                 .kv("bytes_written", r.bytes_written)
                 .kv("stripes_reconstructed", r.stripes_reconstructed);
                if (!r.error.empty()) w.kv("error", r.error);
                w.endObject();
                return w.str();
            });
        json::Writer w;
        w.beginObject().kv("ok", true).kv("job", id).endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- repair -------------------------------------------------------------
    svr.Post("/api/repair", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        Target t = readTarget(body);
        std::string action = body.getStr("action");
        RepairOptions opt;
        opt.apply = body.getBool("apply", false);
        opt.backup = body.getBool("backup", true);
        opt.backup_dir = body.getStr("backup_dir", joinPath(outputRoot(), "repair-backups"));

        if (opt.apply && !g_allowWrites) {
            res.set_content(errorJson(
                "writing repairs is disabled",
                "restart the engine with --allow-writes to permit modifying the device"),
                "application/json");
            return;
        }

        std::string err;
        auto disk = openTarget(t.path, t.offset, t.length, &err);
        if (!disk) {
            res.set_content(errorJson(err), "application/json");
            return;
        }
        RepairResult r = repairVolume(*disk, action, opt);
        json::Writer w;
        w.beginObject().kv("ok", true).key("result").beginObject();
        w.kv("ok", r.ok).kv("applied", r.applied).kv("action", r.action)
         .kv("detail", r.detail).kv("error", r.error);
        w.key("steps").beginArray();
        for (const auto& s : r.steps) w.value(s);
        w.endArray();
        w.endObject().endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- save arbitrary bytes ----------------------------------------------
    svr.Post("/api/save", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = json::parse(req.body);
        std::string dir = body.getStr("output_dir", joinPath(outputRoot(), "saved"));
        if (!pathIsWithin(dir, outputRoot()) && realPathOf(dir) != realPathOf(outputRoot())) {
            res.set_content(errorJson("output_dir must be inside " + outputRoot()),
                            "application/json");
            return;
        }
        auto bytes = base64Decode(body.getStr("data_b64"));
        SaveResult r = saveBytes(dir, body.getStr("filename", "recovered.bin"), bytes);
        json::Writer w;
        w.beginObject().kv("ok", r.ok);
        if (r.ok) w.kv("path", r.path).kv("size", r.size);
        else w.kv("error", r.error);
        w.endObject();
        res.set_content(w.str(), "application/json");
    });

    // ---- static UI ----------------------------------------------------------
    auto serveStatic = [webRoot](const std::string& file, const char* mime,
                                 httplib::Response& res) {
        if (webRoot.empty()) {
            res.status = 500;
            res.set_content("GHOST//RECOVER: web assets not found. Run the binary from the "
                            "ghost-recover directory, or install the web/ directory next to it.",
                            "text/plain");
            return;
        }
        std::ifstream f(joinPath(webRoot, file), std::ios::binary);
        if (!f) {
            res.status = 404;
            res.set_content("not found", "text/plain");
            return;
        }
        std::string body((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        res.set_content(body, mime);
    };

    svr.Get("/", [&](const httplib::Request&, httplib::Response& res) {
        serveStatic("index.html", "text/html; charset=utf-8", res);
    });
    svr.Get("/app.js", [&](const httplib::Request&, httplib::Response& res) {
        serveStatic("app.js", "text/javascript; charset=utf-8", res);
    });
    svr.Get("/styles.css", [&](const httplib::Request&, httplib::Response& res) {
        serveStatic("styles.css", "text/css; charset=utf-8", res);
    });

    g_server = &svr;

    const std::string bind = cfg.allow_remote ? "0.0.0.0" : cfg.bind_address;

    // If an unprivileged instance spawned us, tell it to stand down and take
    // over its port, so the browser session survives the switch.
    bool takingOver = false;
    bool parentRejected = false;
    if (!cfg.takeover_file.empty()) {
        std::ifstream tf(cfg.takeover_file);
        std::string token;
        std::getline(tf, token);
        tf.close();
        if (token.empty()) {
            fprintf(stderr, "ERROR: handover token file %s is empty\n", cfg.takeover_file.c_str());
        } else {
            httplib::Client cli("127.0.0.1", cfg.port);
            cli.set_connection_timeout(2, 0);
            cli.set_read_timeout(5, 0);
            json::Writer w;
            w.beginObject().kv("token", token).endObject();
            auto r = cli.Post("/api/handover", w.str(), "application/json");
            if (r && r->status == 200) {
                takingOver = true;
                printf("taking over port %d from the unprivileged instance\n", cfg.port);
            } else if (r && r->status == 403) {
                // A live engine answered but rejected the token. It is not the
                // parent that spawned us (that would have accepted), so binding
                // alongside it would split every request between two engines.
                // Refuse to start rather than serve half a page per round trip.
                parentRejected = true;
                fprintf(stderr, "ERROR: the engine on port %d refused the handover token\n",
                        cfg.port);
            } else {
                printf("no unprivileged instance answered on port %d; starting normally\n",
                       cfg.port);
            }
            ::unlink(cfg.takeover_file.c_str());
        }
    }

    printf("GHOST//RECOVER engine %s\n", kVersion);
    printf("  listening on http://%s:%d\n", bind.c_str(), cfg.port);
    printf("  output root: %s\n", outputRoot().c_str());
    printf("  %zu carver signatures, %zu filesystems, repair writes %s\n",
           carverRegistry().size(), filesystemRegistry().size(),
           g_allowWrites ? "ENABLED" : "disabled");
    if (::getuid() != 0)
        printf("  note: not running as root — raw block devices will not be readable\n");
    fflush(stdout);

    if (parentRejected) return 1;

    // Reconnect, don't duplicate: when we are not taking over, a live engine
    // already answering on the port — usually the privileged instance left
    // running from an earlier unlock — is already serving. SO_REUSEPORT would
    // let a same-UID second instance bind alongside it (splitting every
    // request between two engines), so detect it before binding and just point
    // the browser at it.
    if (!takingOver && liveEngineOnPort(cfg.port)) {
        printf("an engine is already running on port %d — connecting to it\n", cfg.port);
        fflush(stdout);
        if (cfg.open_browser)
            launchBrowser("http://localhost:" + std::to_string(cfg.port));
        return 0;
    }

    // The page is only opened once the port actually accepts connections, so a
    // slow bind — or a bind that never succeeds — never leaves the user staring
    // at "localhost refused to connect".
    if (cfg.open_browser) {
        std::thread([port = cfg.port]() {
            for (int i = 0; i < 40; i++) {
                int sock = ::socket(AF_INET, SOCK_STREAM, 0);
                if (sock >= 0) {
                    sockaddr_in sa{};
                    sa.sin_family = AF_INET;
                    sa.sin_port = htons((unsigned short)port);
                    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                    if (::connect(sock, (sockaddr*)&sa, sizeof(sa)) == 0) {
                        ::close(sock);
                        launchBrowser("http://localhost:" + std::to_string(port));
                        return;
                    }
                    ::close(sock);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }).detach();
    }

    // When taking over, the previous instance needs a moment to close its
    // listening socket. SO_REUSEADDR lets us rebind over the old socket's
    // TIME_WAIT, so this almost always succeeds on the second attempt.
    //
    // httplib latches `is_decommissioned` on the first failed bind and every
    // later bind short-circuits to -1 without touching the network, so the
    // retry loop below would otherwise be a no-op after the first attempt.
    // stop() clears that latch (when the server is not running it just resets
    // the flag), which is what makes the retries real.
    const int attempts = takingOver ? 120 : 1;
    // Let the old instance finish its 250ms response-flush and close its
    // listening socket BEFORE we bind. Binding earlier would make, for
    // example, a browser request during the switch land on the closing
    // instance (connection reset) or, worse, split traffic between two
    // engines that both think they own the port.
    if (takingOver) std::this_thread::sleep_for(std::chrono::milliseconds(300));
    for (int i = 0; i < attempts; i++) {
        svr.stop();
        if (svr.listen(bind.c_str(), cfg.port)) {
            g_server = nullptr;
            return 0;
        }
        if (i + 1 < attempts) std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
    g_server = nullptr;
    // Fallback: binding failed, but a live engine may still hold the port —
    // most commonly the privileged instance from an earlier unlock (different
    // UID, so SO_REUSEPORT refused the bind), which keeps serving after the
    // browser tab was closed. That is "already running", not an error.
    if (liveEngineOnPort(cfg.port)) {
        printf("an engine is already running on port %d — connecting to it\n", cfg.port);
        fflush(stdout);
        if (cfg.open_browser)
            launchBrowser("http://localhost:" + std::to_string(cfg.port));
        return 0;
    }
    fprintf(stderr, "ERROR: could not bind %s:%d (is another instance running?)\n",
            bind.c_str(), cfg.port);
    return 1;
}

}  // namespace ghost
