// GHOST//RECOVER — HTTP API server.
#pragma once

#include "ghost/types.h"

namespace ghost {

struct ServerConfig {
    int         port         = 3030;
    std::string bind_address = "127.0.0.1";   // loopback by default: this API can read raw disks
    std::string web_root;                     // auto-detected when empty
    std::string output_root;                  // defaults to defaultOutputRoot()
    bool        allow_repair_writes = false;  // --allow-writes
    bool        allow_remote        = false;  // --listen 0.0.0.0
    bool        open_browser        = true;   // --no-browser; never set with --takeover

    // Set on the elevated instance that a running unprivileged instance
    // spawned. It names a file holding a one-time token; the new instance
    // presents it to the old one to claim the port, so the browser keeps the
    // same URL across the switch. See docs in server.cpp.
    std::string takeover_file;
};

int startServer(const ServerConfig& cfg);

// Where the engine is allowed to read files from and write results to. Serving
// and extraction are confined to these roots so the API cannot be used to read
// arbitrary files off the host.
const std::string& outputRoot();
void setOutputRoot(const std::string& p);
bool pathAllowedForServing(const std::string& p);

// ---------------------------------------------------------------------------
// Privilege elevation
//
// Reading a physical disk needs root. Rather than telling the user to go and
// restart the program themselves, the running instance can launch a privileged
// copy of itself and hand the port over to it.
// ---------------------------------------------------------------------------
struct ElevationMethods {
    bool is_root        = false;
    bool pkexec         = false;   // polkit available and a graphical session exists
    bool sudo           = false;   // sudo installed
    bool sudo_nopasswd  = false;   // sudo already authorised without a password
    bool has_display    = false;
    std::string preferred;         // "pkexec" | "sudo-nopasswd" | "sudo-password" | ""
    std::string note;              // why elevation may not work here
};

ElevationMethods detectElevationMethods();

const char* engineVersion();

}  // namespace ghost
