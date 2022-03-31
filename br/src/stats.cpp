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

#include "stats.hpp"

extern "C" {
#include "bpf/common.h"
}

#include "libbpfpp/util.hpp"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <vector>

using std::uint64_t;


namespace {

struct Rates
{
    double verdict_bytes[COUNTER_ENUM_COUNT];
    double verdict_pkts[COUNTER_ENUM_COUNT];
};

void calcRates(
    const struct port_stats &stats,
    const struct port_stats &prevStats,
    std::chrono::nanoseconds deltaT,
    struct Rates &rates)
{
    double deltaSeconds = 1e-9 * static_cast<double>(deltaT.count());
    for (int i = 0; i < COUNTER_ENUM_COUNT; ++i)
    {
        uint64_t bytes = stats.verdict_bytes[i] - prevStats.verdict_bytes[i];
        rates.verdict_bytes[i] = static_cast<double>(bytes) / deltaSeconds;
        uint64_t pkts = stats.verdict_pkts[i] - prevStats.verdict_pkts[i];
        rates.verdict_pkts[i] = static_cast<double>(pkts) / deltaSeconds;
    }
}

bool getStats(const Bpf::PinnedMap &map, uint32_t ifindex, struct port_stats &totals)
{
    std::vector<struct port_stats> stats(sysconf(_SC_NPROCESSORS_ONLN));
    bool res = map.lookup(
        &ifindex, sizeof(ifindex), stats.data(), stats.size() * sizeof(struct port_stats));
    if (!res) return res;

    std::memset(&totals, 0, sizeof(totals));
    for (const auto& cpu : stats)
    {
        for (int i = 0; i < COUNTER_ENUM_COUNT; ++i)
        {
            totals.verdict_bytes[i] += cpu.verdict_bytes[i];
            totals.verdict_pkts[i] += cpu.verdict_pkts[i];
        }
    }

    return true;
}

void printStats(const struct port_stats &stats, const Rates &rates)
{
    static const char* STAT_NAMES[COUNTER_ENUM_COUNT] = {
        "Undefined",
        "Forwarded",
        "Parse error",
        "Not SCION",
        "Not implemented",
        "No interface",
        "Router alert",
        "FIB lookup drop",
        "FIB lookup pass",
        "Invalid HF",
    };

    std::cout << "Verdict           Packets    pkts/s         Bytes    Mbit/s\n";
    for (int i = 0; i < COUNTER_ENUM_COUNT; ++i)
    {
        std::cout
            << std::left << std::setw(16) << STAT_NAMES[i]
            << std::right << std::setw(8) << stats.verdict_pkts[i]
            << std::setw(11) << std::fixed << std::setprecision(0) << rates.verdict_pkts[i]
            << std::setw(14) << stats.verdict_bytes[i]
            << std::setw(10) << std::defaultfloat << std::setprecision(5)
            << rates.verdict_bytes[i] * 8e-6
            << '\n';
    }
}

} // namespace

void watchStats(const Bpf::PinnedMap &map, uint32_t ifindex)
{
    Bpf::Util::InterruptSignalHandler signalHandler;
    struct port_stats stats, prevStats;
    Rates rates = {};

    auto t0 = std::chrono::high_resolution_clock::now();
    if (!getStats(map, ifindex, stats))
    {
        std::cerr << "Lookup failed\n";
        return;
    }
    printStats(stats, rates);

    signalHandler.launchHandler();
    while (!signalHandler.wait(std::chrono::seconds(1)))
    {
        auto t1 = std::chrono::high_resolution_clock::now();
        auto deltaT = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0);
        t0 = t1;
        prevStats = stats;
        if (!getStats(map, ifindex, stats))
        {
            std::cerr << "Lookup failed\n";
            break;
        }
        calcRates(stats, prevStats, deltaT, rates);
        printStats(stats, rates);
    }
    signalHandler.joinHandler();
}
