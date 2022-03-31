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

#include "libbpfpp/util.hpp"

extern "C" {
#include <poll.h>
#include <stdio.h>
}

#include <iostream>


namespace Bpf {
namespace Util {

////////////////////////////
// InterruptSignalHandler //
////////////////////////////

InterruptSignalHandler::InterruptSignalHandler()
{
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
}

void InterruptSignalHandler::launchHandler()
{
    // Do not receive signals in sigset on this thread or any threads spawned by it.
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);

    // Start a new thread waiting for a signal to terminate (e.g, Ctrl+C).
    auto handler = [this]() {
        int signum = 0;
        sigwait(&sigset, &signum);

        terminate = true;
        cv.notify_all();

        return signum;
    };
    handlerThread = std::thread(handler);
}

void InterruptSignalHandler::joinHandler()
{
    kill(0, SIGTERM);
    handlerThread.join();
}

bool InterruptSignalHandler::wait(std::chrono::high_resolution_clock::duration timeout) const
{
    std::unique_lock lock(mutex);
    cv.wait_for(lock, timeout, [this] {
        return terminate == true;
    });
    return terminate;
}

////////////////
// tracePrint //
////////////////

bool tracePrint(const InterruptSignalHandler &cond)
{
    static const char* TRACEFS_PIPE = "/sys/kernel/debug/tracing/trace_pipe";
    char *line = NULL;
    std::size_t lineLen = 0;

    FILE* stream = fopen(TRACEFS_PIPE, "r");
    if (!stream) {
        std::cerr << "Cannot open kernel trace file" << std::endl;
        return false;
    }

    struct pollfd fds = {
        .fd = fileno(stream),
        .events = POLLIN,
    };

    try {
        while (!cond.wait(std::chrono::milliseconds(100)))
        {
            while (poll(&fds, 1, 0))
            {
                std::size_t readChars = getline(&line, &lineLen, stream);
                if (readChars < 0) {
                    std::cerr << "Error reading kernel trace file" << std::endl;
                    return false;
                }
                std::cout << line;
            }
        }
    }
    catch (...) {
        free(line);
        fclose(stream);
        throw;
    }

    free(line);
    fclose(stream);
    return true;
}

} // namespace Util
} // namespace Bpf
