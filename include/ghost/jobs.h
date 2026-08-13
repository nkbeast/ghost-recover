// GHOST RECOVER — background job manager.
//
// Scanning a 2 TB drive takes hours. The previous engine ran those scans inside
// the HTTP handler with a 120 s socket timeout, so any real workload either
// timed out or left the browser with a dead spinner and no way to cancel.
// Long operations now run on worker threads and the UI polls for progress.
#pragma once

#include "ghost/types.h"

#include <atomic>
#include <condition_variable>
#include <set>
#include <thread>

namespace ghost {

enum class JobState { Queued, Running, Done, Failed, Cancelled };

const char* jobStateName(JobState s);

struct Job {
    std::string id;
    std::string kind;        // "scan" | "carve" | "deep" | "extract" | "image" | ...
    std::string target;      // device/image path, for display
    u64         seq = 0;     // submission order; the serialisation gate runs
                             // the lowest outstanding seq first (FIFO)
    std::atomic<JobState> state{JobState::Queued};
    Progress    progress;
    // Written by the worker thread, read by the HTTP thread while the job is
    // still running — plain i64 fields were a data race.
    std::atomic<i64>    created_ms  {0};
    std::atomic<i64>    started_ms  {0};
    std::atomic<i64>    finished_ms {0};

    mutable std::mutex mu;
    std::string result_json;   // guarded by mu
    std::string error;         // guarded by mu

    std::string resultJson() const { std::lock_guard<std::mutex> lk(mu); return result_json; }
    std::string errorText()  const { std::lock_guard<std::mutex> lk(mu); return error; }
    bool terminal() const {
        JobState s = state.load();
        return s == JobState::Done || s == JobState::Failed || s == JobState::Cancelled;
    }
};

using JobFn = std::function<std::string(Job&)>;   // returns the result JSON

class JobManager {
public:
    static JobManager& instance();

    // Starts `fn` on a worker thread and returns the new job id immediately.
    // Heavy jobs (scan/carve/deep/extract/image/raid) are serialised: at most
    // one runs at a time and the rest wait in "queued" state. Two concurrent
    // scans of a large disk each hold their whole result in RAM, so on a 1 GiB
    // box a second job was the difference between slow and OOM-killed.
    std::string submit(const std::string& kind, const std::string& target, JobFn fn);

    std::shared_ptr<Job> get(const std::string& id) const;
    std::vector<std::shared_ptr<Job>> list() const;
    bool cancel(const std::string& id);
    // True when any job is queued or running (the idle watchdog must not shut
    // the engine down mid-scan).
    bool hasRunningJob() const;
    // Drops terminal jobs older than `maxAgeMs`, keeping at most `keep` of them.
    void prune(i64 maxAgeMs = 3600 * 1000, size_t keep = 100);
    void shutdown();

private:
    JobManager() = default;
    ~JobManager();

    mutable std::mutex mu_;
    std::map<std::string, std::shared_ptr<Job>> jobs_;
    std::vector<std::thread> workers_;   // joined on shutdown, guarded by mu_
    u64  counter_ = 0;
    bool stopping_ = false;

    // Serialisation gate: only the job whose seq matches nextToRun_ may run;
    // everyone else waits on gateCv_ holding no lock at all. When the turn is
    // passed (completion or a cancelled job leaving the queue) nextToRun_
    // advances past any cancelled entries still in line, so jobs run strictly
    // in submission order and a cancel can never wedge the queue.
    std::mutex              gate_;
    std::condition_variable gateCv_;
    u64                     nextToRun_ = 1;
    std::set<u64>           skipped_;   // cancelled-while-queued seqs (guarded by gate_)

    void advanceLine();                 // caller holds gate_
};

}  // namespace ghost
