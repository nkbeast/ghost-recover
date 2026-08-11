#include "ghost/jobs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstdio>

namespace ghost {

const char* jobStateName(JobState s) {
    switch (s) {
        case JobState::Queued:    return "queued";
        case JobState::Running:   return "running";
        case JobState::Done:      return "done";
        case JobState::Failed:    return "failed";
        case JobState::Cancelled: return "cancelled";
    }
    return "unknown";
}

JobManager& JobManager::instance() {
    static JobManager m;
    return m;
}

JobManager::~JobManager() { shutdown(); }

void JobManager::shutdown() {
    const std::lock_guard<std::mutex> lk(mu_);
    stopping_ = true;
    for (auto& [id, j] : jobs_) j->progress.cancel();
}

std::string JobManager::submit(const std::string& kind, const std::string& target, JobFn fn) {
    auto job = std::make_shared<Job>();
    {
        std::lock_guard<std::mutex> lk(mu_);
        if (stopping_) return {};
        char buf[64];
        snprintf(buf, sizeof(buf), "%s-%llu", kind.c_str(), (unsigned long long)(++counter_));
        job->id = buf;
        job->kind = kind;
        job->target = target;
        job->created_ms = nowMs();
        jobs_[job->id] = job;
    }

    std::thread worker([job, fn]() {
        job->state = JobState::Running;
        job->started_ms = nowMs();
        std::string out;
        std::string err;
        try {
            out = fn(*job);
        } catch (const std::exception& e) {
            err = e.what();
        } catch (...) {
            err = "unknown exception in worker";
        }
        job->finished_ms = nowMs();
        {
            // Result and state are decided under one lock so a concurrent
            // cancel() can never observe a "running" job that already stored
            // a terminal state (or vice versa).
            const std::lock_guard<std::mutex> lk(job->mu);
            job->result_json = out;
            if (!err.empty()) job->error = err;
            if (!err.empty())                   job->state = JobState::Failed;
            else if (job->progress.cancelled()) job->state = JobState::Cancelled;
            else                                job->state = JobState::Done;
        }
        job->progress.setPhase(jobStateName(job->state.load()));
    });

    // Detached rather than tracked: a finished std::thread stays joinable, so
    // holding them meant one leaked OS handle per job for the life of the
    // server. Cancellation goes through the job's own flag.
    worker.detach();
    return job->id;
}

std::shared_ptr<Job> JobManager::get(const std::string& id) const {
    const std::lock_guard<std::mutex> lk(mu_);
    auto it = jobs_.find(id);
    return it == jobs_.end() ? nullptr : it->second;
}

std::vector<std::shared_ptr<Job>> JobManager::list() const {
    const std::lock_guard<std::mutex> lk(mu_);
    std::vector<std::shared_ptr<Job>> out;
    out.reserve(jobs_.size());
    for (const auto& [id, j] : jobs_) out.push_back(j);
    std::sort(out.begin(), out.end(),
              [](const std::shared_ptr<Job>& a, const std::shared_ptr<Job>& b) {
                  return a->created_ms > b->created_ms;
              });
    return out;
}

bool JobManager::cancel(const std::string& id) {
    auto j = get(id);
    if (!j) return false;
    {
        std::lock_guard<std::mutex> lk(j->mu);
        if (j->terminal()) return false;
        j->progress.cancel();
        j->progress.setPhase("cancelling");
    }
    return true;
}

void JobManager::prune(i64 maxAgeMs, size_t keep) {
    const std::lock_guard<std::mutex> lk(mu_);
    const i64 now = nowMs();
    std::vector<std::pair<i64, std::string>> terminal;
    for (const auto& [id, j] : jobs_)
        if (j->terminal()) terminal.emplace_back(j->finished_ms, id);
    std::sort(terminal.begin(), terminal.end());
    for (size_t i = 0; i < terminal.size(); i++) {
        const bool tooOld  = (now - terminal[i].first) > maxAgeMs;
        const bool tooMany = (terminal.size() - i) > keep;
        if (tooOld || tooMany) jobs_.erase(terminal[i].second);
    }
}

}  // namespace ghost
