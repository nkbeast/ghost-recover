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

// Moves the gate's turn forward past any cancelled-while-queued entries.
// Caller must hold gate_.
void JobManager::advanceLine() {
    do {
        nextToRun_++;
    } while (skipped_.erase(nextToRun_));
}

void JobManager::shutdown() {
    {
        const std::lock_guard<std::mutex> lk(mu_);
        stopping_ = true;
        for (auto& [id, j] : jobs_) j->progress.cancel();
    }
    // Join the workers rather than leaving them detached: after shutdown()
    // returns the caller's process may tear down, and a still-running worker
    // (mid-scan, mid-extract) touching engine state would crash the exit.
    std::vector<std::thread> workers;
    {
        const std::lock_guard<std::mutex> lk(mu_);
        workers.swap(workers_);
    }
    for (auto& t : workers)
        if (t.joinable()) t.join();
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
        job->seq = counter_;
        job->created_ms = nowMs();
        jobs_[job->id] = job;
    }

    std::thread worker([this, job, fn]() {
        // Wait for the serialisation gate. The state stays Queued while
        // waiting, so the UI shows an honest "queued" instead of a fake
        // "running" that never advances. Only the job with the lowest
        // outstanding seq runs; the rest wait in submission order.
        bool skip = false;
        {
            std::unique_lock<std::mutex> lk(gate_);
            // wait_for instead of wait: cancel() only sets a flag and can
            // never notify the shared gate, so a queued job must re-check its
            // own cancellation every so often while it waits its turn. The
            // predicate form returns the predicate's value, so on timeout
            // (false) the loop simply keeps waiting.
            while (!(stopping_ || job->progress.cancelled() ||
                     job->seq == nextToRun_))
                gateCv_.wait_for(lk, std::chrono::milliseconds(500));
            skip = stopping_ || job->progress.cancelled();
            if (skip) {
                // Record our place in the line so the turn-holder's
                // advanceLine() can jump straight past us — even if we are not
                // the holder (the line may not reach our seq for a while).
                skipped_.insert(job->seq);
                if (job->seq == nextToRun_)
                    advanceLine();      // we were the holder: pass the turn on
            } else {
                {
                    // State and timing are recorded under the same lock as the
                    // terminal store below; a concurrent cancel()/prune()
                    // therefore never sees a job mid-transition or stuck on
                    // "running" after it already stored its result.
                    const std::lock_guard<std::mutex> jl(job->mu);
                    job->state = JobState::Running;
                    job->started_ms = nowMs();
                }
            }
            lk.unlock();
            if (skip) {
                gateCv_.notify_all();
                job->finished_ms = nowMs();
                {
                    const std::lock_guard<std::mutex> jl(job->mu);
                    job->state = JobState::Cancelled;
                    job->error = "cancelled";
                }
                job->progress.setPhase("cancelled");
                return;
            }
        }
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
            const std::lock_guard<std::mutex> jl(job->mu);
            job->result_json = out;
            if (!err.empty()) job->error = err;
            if (!err.empty())                   job->state = JobState::Failed;
            else if (job->progress.cancelled()) job->state = JobState::Cancelled;
            else                                job->state = JobState::Done;
        }
        job->progress.setPhase(jobStateName(job->state.load()));
        {
            const std::lock_guard<std::mutex> gl(gate_);
            advanceLine();           // pass the turn to the next queued job
        }
        gateCv_.notify_all();
    });

    // Tracked rather than detached so shutdown() can join every worker.
    // Finished threads are joined once and drop out of the list naturally.
    {
        const std::lock_guard<std::mutex> lk(mu_);
        if (stopping_) {                // raced a shutdown: abandon the thread
            worker.detach();
            return {};
        }
        workers_.push_back(std::move(worker));
    }
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
