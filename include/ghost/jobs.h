// GHOST//RECOVER — background job manager.
//
// Scanning a 2 TB drive takes hours. The previous engine ran those scans inside
// the HTTP handler with a 120 s socket timeout, so any real workload either
// timed out or left the browser with a dead spinner and no way to cancel.
// Long operations now run on worker threads and the UI polls for progress.
#pragma once

#include "ghost/types.h"

#include <atomic>
#include <condition_variable>
#include <thread>

namespace ghost {

enum class JobState { Queued, Running, Done, Failed, Cancelled };

const char* jobStateName(JobState s);

struct Job {
    std::string id;
    std::string kind;        // "scan" | "carve" | "deep" | "extract" | "image" | ...
    std::string target;      // device/image path, for display
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
    std::string submit(const std::string& kind, const std::string& target, JobFn fn);

    std::shared_ptr<Job> get(const std::string& id) const;
    std::vector<std::shared_ptr<Job>> list() const;
    bool cancel(const std::string& id);
    // Drops terminal jobs older than `maxAgeMs`, keeping at most `keep` of them.
    void prune(i64 maxAgeMs = 3600 * 1000, size_t keep = 100);
    void shutdown();

private:
    JobManager() = default;
    ~JobManager();

    mutable std::mutex mu_;
    std::map<std::string, std::shared_ptr<Job>> jobs_;
    u64  counter_ = 0;
    bool stopping_ = false;
};

}  // namespace ghost
