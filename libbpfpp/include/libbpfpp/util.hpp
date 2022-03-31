// Copyright (c) 2022 Lars-Christian Schulz
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

extern "C" {
#include <signal.h>
}

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>


namespace Bpf {
namespace Util {

/// \brief Helper for dealing with process termination signals.
class InterruptSignalHandler
{
public:
    InterruptSignalHandler();

    /// \brief Evaluates to true, if the process should terminate.
    operator bool() const { return terminate; }

    /// \brief Start a new thread waiting for SIGINT or SIGTERM. SIGINT and SIGTERM will be masked
    /// on the calling thread.
    /// \remark Call in main thread before other threads are spawned.
    void launchHandler();

    /// \brief Terminate and join with the handler thread.
    void joinHandler();

    /// \brief Wait for a request to terminate the program or until the timeout has elapsed.
    /// \return True if the program should terminate, false if the timeout has elapsed.
    bool wait(std::chrono::high_resolution_clock::duration timeout) const;

private:
    sigset_t sigset;
    std::atomic<bool> terminate = false;
    mutable std::mutex mutex;
    mutable std::condition_variable cv;
    std::thread handlerThread;
};

/// \brief Print lines from `/sys/kernel/debug/tracing/trace_pipe` until \p cond indicates the
/// program should terminate.
/// \return False on error, true on normal termination.
bool tracePrint(const InterruptSignalHandler &cond);

} // namespace Util
} // namespace Bpf
