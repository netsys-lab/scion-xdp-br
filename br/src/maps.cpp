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

#include "maps.hpp"
#include "config.hpp"
#include "ifindex.hpp"

#include "libbpfpp/map.hpp"

extern "C" {
#include "aes/aes.h"
#include "bpf/common.h"
}

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <stdexcept>

using std::size_t;
using std::uint8_t;
using std::uint32_t;


////////////////////////
// Internal Functions //
////////////////////////

namespace {

#ifdef ENABLE_IPV4
void storeIPv4(const boost::asio::ip::address_v4 &ip, uint8_t *__restrict__ dst)
{
    uint32_t addr = htonl(ip.to_uint());
    std::memcpy(dst, &addr, sizeof(addr));
}
#endif

#ifdef ENABLE_IPV6
void storeIPv6(const boost::asio::ip::address_v6 &ip, uint8_t *__restrict__ dst)
{
    auto bytes = ip.to_bytes();
    std::copy(bytes.begin(), bytes.end(), dst);
}
#endif

#ifdef ENABLE_IPV4
#define STORE_IPV4(ip, dst) storeIPv4(ip, reinterpret_cast<uint8_t*>(dst))
#else
#define STORE_IPV4(ip, dst) throw std::runtime_error( \
    "Border router configuration contains IPv4 address, but IPv4 support is deactivated.")
#endif

#ifdef ENABLE_IPV6
#define STORE_IPV6(ip, dst) storeIPv6(ip, reinterpret_cast<uint8_t*>(dst))
#else
#define STORE_IPV6(ip, dst) throw std::runtime_error( \
    "Border router configuration contains IPv6 address, but IPv6 support is deactivated.");
#endif

#ifdef ENABLE_HF_CHECK
void populateSBox(Bpf::Map &sboxMap)
{
    uint32_t key = 0;
    const uint8_t *value = AES_SBox;
    sboxMap.update(&key, sizeof(key), value, 256, BPF_ANY);
}
#endif

void populateIngressMap(Bpf::Map &ingressMap, const BrConfig &config)
{
    for (const auto &iface : config.ifs.external)
    {
        if (iface.ifname.empty()) continue;
        auto ifindex = ifNameToIndex(iface.ifname.c_str());
        struct ingress_addr key = {
            .port = htons(iface.local.port),
            .ifindex = static_cast<u16>(ifindex),
        };
        if (iface.local.ip.is_v4())
            STORE_IPV4(iface.local.ip.to_v4(), &key.ipv4);
        else
            STORE_IPV6(iface.local.ip.to_v6(), &key.ipv6);
        uint32_t value = iface.scionIfId;
        ingressMap.update(&key, sizeof(key), &value, sizeof(value), 0);
    }
}

void populateEgressMap(Bpf::Map &egressMap, const BrConfig &config)
{
    // Interfaces to other ASes
    for (const auto &iface : config.ifs.external)
    {
        struct fwd_info fwd = {
            .fwd_external = true,
            .link = {
                .remote_port = htons(iface.remote.port),
                .local_port = htons(iface.local.port)
            }
        };
        assert(iface.local.ip.is_v4() == iface.remote.ip.is_v4());
        if (iface.local.ip.is_v4())
        {
            fwd.link.ip_family = AF_INET;
            STORE_IPV4(iface.local.ip.to_v4(), &fwd.link.ipv4.local);
            STORE_IPV4(iface.remote.ip.to_v4(), &fwd.link.ipv4.remote);
        }
        else
        {
            fwd.link.ip_family = AF_INET6;
            STORE_IPV6(iface.local.ip.to_v6(), &fwd.link.ipv6.local);
            STORE_IPV6(iface.remote.ip.to_v6(), &fwd.link.ipv6.remote);
        }

        uint32_t key = iface.scionIfId;
        egressMap.update(&key, sizeof(key), &fwd, sizeof(fwd), 0);
    }

    // Interfaces to other ASes attached to another border router
    for (const auto &iface : config.ifs.sibling)
    {
        struct fwd_info fwd = {
            .fwd_external = false,
            .sibling = { .port = htons(iface.sibling.port) }
        };
        if (iface.sibling.ip.is_v4())
        {
            fwd.sibling.ip_family = AF_INET;
            STORE_IPV4(iface.sibling.ip.to_v4(), &fwd.sibling.ipv4);
        }
        else
        {
            fwd.sibling.ip_family = AF_INET6;
            STORE_IPV6(iface.sibling.ip.to_v6(), &fwd.sibling.ipv6);
        }

        uint32_t key = iface.scionIfId;
        egressMap.update(&key, sizeof(key), &fwd, sizeof(fwd), 0);
    }
}

void populateIntIfMap(Bpf::Map &intIfMap, const BrConfig &config)
{
    for (const auto &iface : config.ifs.internal)
    {
        if (iface.ifname.empty()) continue;
        struct int_iface intIf = {
            .port = htons(iface.local.port)
        };
        if (iface.local.ip.is_v4())
        {
            intIf.ip_family = AF_INET;
            STORE_IPV4(iface.local.ip.to_v4(), &intIf.ipv4);
        }
        else
        {
            intIf.ip_family = AF_INET6;
            STORE_IPV6(iface.local.ip.to_v6(), &intIf.ipv6);
        }
        auto ifindex = static_cast<uint32_t>(ifNameToIndex(iface.ifname.c_str()));
        intIfMap.update(&ifindex, sizeof(ifindex), &intIf, sizeof(intIf), 0);
    }
}

void populatePortMap(Bpf::Map &txPortMap, const BrConfig &config)
{
    for (const auto &iface : config.ifs.external)
    {
        if (iface.ifname.empty()) continue;
        uint32_t ifindex = ifNameToIndex(iface.ifname.c_str());
        txPortMap.update(&ifindex, sizeof(ifindex), &ifindex, sizeof(ifindex), 0);
    }
    for (const auto &iface : config.ifs.internal)
    {
        if (iface.ifname.empty()) continue;
        uint32_t ifindex = ifNameToIndex(iface.ifname.c_str());
        txPortMap.update(&ifindex, sizeof(ifindex), &ifindex, sizeof(ifindex), 0);
    }
}

void initPortStats(Bpf::Map &statsMap, const std::vector<unsigned int> &interfaces)
{
    std::vector<struct port_stats> value(sysconf(_SC_NPROCESSORS_ONLN));
    for (uint32_t ifindex : interfaces)
    {
        statsMap.update(
            &ifindex, sizeof(ifindex), value.data(),
            value.size() * sizeof(struct port_stats), 0);
    }
}

void initScratchpad(Bpf::Map &scratchpad, const BrConfig &config)
{
    std::vector<struct scratchpad> data(sysconf(_SC_NPROCESSORS_ONLN));
    uint32_t key = 0;
    scratchpad.update(&key, sizeof(key), data.data(), data.size() * sizeof(struct scratchpad), 0);
}

void printWarning(const char *mapName)
{
    std::cerr << "WARNING: Map " << mapName << " not found or of incompatible type.\n";
}

} // namespace

////////////////////
// initializeMaps //
////////////////////

void initializeMaps(
    const Bpf::Object &bpf,
    const BrConfig &config,
    const std::vector<unsigned int> &interfaces
)
{
    const char *mapName = nullptr;
    std::optional<Bpf::BpfLibMap> map;

#ifdef ENABLE_HF_CHECK
    mapName = "AES_SBox";
    map = bpf.findMapByName(mapName, BPF_MAP_TYPE_ARRAY);
    if (map) populateSBox(*map);
    else printWarning(mapName);
#endif

    mapName = "ingress_map";
    map = bpf.findMapByName(mapName, BPF_MAP_TYPE_HASH);
    if (map) populateIngressMap(*map, config);
    else printWarning(mapName);

    mapName = "egress_map";
    map = bpf.findMapByName(mapName, BPF_MAP_TYPE_HASH);
    if (map) populateEgressMap(*map, config);
    else printWarning(mapName);

    mapName = "int_iface_map";
    map = bpf.findMapByName(mapName, BPF_MAP_TYPE_HASH);
    if (map) populateIntIfMap(*map, config);
    else printWarning(mapName);

    mapName = "tx_port_map";
    map = bpf.findMapByName(mapName, BPF_MAP_TYPE_DEVMAP);
    if (map) populatePortMap(*map, config);
    else printWarning(mapName);

    mapName = "port_stats_map";
    map = bpf.findMapByName(mapName, BPF_MAP_TYPE_PERCPU_HASH);
    if (map) initPortStats(*map, interfaces);
    else printWarning(mapName);

    mapName = "scratchpad_map";
    map = bpf.findMapByName(mapName, BPF_MAP_TYPE_PERCPU_ARRAY);
    if (map) initScratchpad(*map, config);
    else printWarning(mapName);
}
