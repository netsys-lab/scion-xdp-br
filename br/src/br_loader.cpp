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

extern "C" {
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf.h>
#include "aes/aes.h"
#include "bpf/common.h"
}

#include "config.hpp"
#include "ifindex.hpp"
#include "maps.hpp"
#include "stats.hpp"

#include "libbpfpp/libbpfpp.hpp"
#include "libbpfpp/map.hpp"

#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>

#include <cstdlib>
#include <stdexcept>
#include <iostream>
#include <filesystem>
#include <string>
#include <vector>

static const char* PIN_BASE_DIR = "/sys/fs/bpf";


static void printUsage()
{
    std::cerr <<
        "Usage: br-loader attach <xdp object> <config> [iface...]\n"
        "                 detach [iface...]\n"
        "                 watch <br> <iface>\n"
    #ifdef ENABLE_HF_CHECK
        "       br-loader key add <br> <index> <key>\n"
        "                 key remove <br> <index>\n"
    #endif
    ;
}

#ifdef ENABLE_HF_CHECK
/// \brief Decode a base64-encoded AES-128 key.
static void decodeKey(const std::string &base64, struct aes_key &key)
{
    using namespace boost::archive::iterators;
    using Iter = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

    if (base64.size() != 24) throw std::invalid_argument("Key has invalid length");
    auto i = Iter(std::begin(base64)), end = Iter(std::end(base64) - 2);
    for (size_t j = 0; i != end && j < sizeof(key); ++i, ++j) key.b[j] = *i;
}
#endif // ENABLE_HF_CHECK

/// \brief Convert interface names given on the command line to interface IDs.
static std::vector<unsigned int> parseInterfaces(int argc, char* argv[])
{
    std::vector<unsigned int> interfaces;
    interfaces.reserve(argc);

    for (int i = 0; i < argc; ++i)
        interfaces.push_back(ifNameToIndex(argv[i]));

    return interfaces;
}

int attachBr(int argc, char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        return EXIT_FAILURE;
    }

    auto interfaces = parseInterfaces(argc - 2, argv + 2);

    // Load and print configuration
    auto config = loadConfig(argv[1]);
    if (!config) return EXIT_FAILURE;
    std::cout << *config;

    auto pinDir = std::filesystem::path(PIN_BASE_DIR) / config->self;
#ifdef ENABLE_HF_CHECK
    auto macKeyMapPath = pinDir / "mac_key_map";
#endif
    auto portStatsMapPath = pinDir / "port_stats_map";

    // Load XDP program
    auto bpf = Bpf::Object::FromFile(argv[0]);
    auto xdp = bpf.findProgramBySection("xdp");
    if (!xdp)
    {
        std::cerr << "XDP program not found\n" << std::endl;
        return -1;
    }
    xdp->setType(BPF_PROG_TYPE_XDP);

#ifdef ENABLE_HF_CHECK
    bool reuseKeyMap = bpf.reusePinnedMap("mac_key_map", macKeyMapPath.c_str());
    if (reuseKeyMap)
        std::cout << "Reusing pinned map: " << macKeyMapPath << "\n";
#endif
    bool reuseStatsMap = bpf.reusePinnedMap("port_stats_map", portStatsMapPath.c_str());
    if (reuseStatsMap)
        std::cout << "Reusing pinned map: " << portStatsMapPath << "\n";

    bpf.load();
    initializeMaps(bpf, *config, interfaces);

    // Pin maps that we need to read or update later
#ifdef ENABLE_HF_CHECK
    if (!reuseKeyMap)
    {
        auto map = bpf.findMapByName("mac_key_map", BPF_MAP_TYPE_HASH);
        if (map) map->pin(macKeyMapPath.c_str());
    }
#endif
    if (!reuseStatsMap)
    {
        auto map = bpf.findMapByName("port_stats_map", BPF_MAP_TYPE_PERCPU_HASH);
        if (map) map->pin(portStatsMapPath.c_str());
    }

    // Attach XDP
    for (int ifindex : interfaces)
        xdp->attachXDP(ifindex, XDP_FLAGS_DRV_MODE);
    std::cout << "XDP-BR attached\n";

    return EXIT_SUCCESS;
}

int detachBr(int argc, char* argv[])
{
    auto interfaces = parseInterfaces(argc, argv);

    for (int ifindex : interfaces)
        Bpf::Program::detachXDP(ifindex, 0);
    std::cout << "XDP-BR detached\n";

    return EXIT_SUCCESS;
}

int watchBr(int argc, char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        return EXIT_FAILURE;
    }

    auto pinPath = std::filesystem::path(PIN_BASE_DIR) / argv[0] / "port_stats_map";
    uint32_t ifindex = ifNameToIndex(argv[1]);

    auto map = Bpf::PinnedMap::Open(pinPath.c_str(), BPF_MAP_TYPE_PERCPU_HASH);
    watchStats(map, ifindex);

    return EXIT_SUCCESS;
}

#ifdef ENABLE_HF_CHECK
int addHopKey(int argc, char* argv[])
{
    if (argc < 3)
    {
        printUsage();
        return EXIT_FAILURE;
    }

    // Construct pinned map path
    auto pinPath = std::filesystem::path(PIN_BASE_DIR) / argv[0] / "mac_key_map";

    // Parse index
    uint32_t index = 0;
    try {
        index = std::stoul(std::string(argv[1]));
    }
    catch (std::exception &e) {
        std::cerr << "Invalid verification key index\n";
        return EXIT_FAILURE;
    }

    // Parse key
    struct aes_key decodedKey = {};
    try {
        decodeKey(std::string(argv[2]), decodedKey);
    }
    catch (std::exception &e) {
        std::cerr << "Invalid MAC verification key: " << e.what() << '\n';
        return EXIT_FAILURE;
    }

    // Calculate key expansion
    struct hop_key hopKey = {};
    aes_key_expansion(&decodedKey, &hopKey.key);
    struct aes_block subkeys[2];
    aes_cmac_subkeys(&hopKey.key, subkeys);
    hopKey.subkey = subkeys[0];

    // Update map
    auto map = Bpf::PinnedMap::Open(pinPath.c_str(), BPF_MAP_TYPE_HASH);
    if (!map.update(&index, sizeof(index), &hopKey, sizeof(hopKey), BPF_ANY))
    {
        std::cerr << "Update failed\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

int removeHopKey(int argc, char* argv[])
{
    if (argc < 2)
    {
        printUsage();
        return EXIT_FAILURE;
    }

    // Construct pinned map path
    auto pinPath = std::filesystem::path(PIN_BASE_DIR) / argv[0] / "mac_key_map";

    // Parse index
    uint32_t index = 0;
    try {
        index = std::stoul(std::string(argv[1]));
    }
    catch (std::exception &e) {
        std::cerr << "Invalid verification key index\n";
        return EXIT_FAILURE;
    }

    // Update map
    auto map = Bpf::PinnedMap::Open(pinPath.c_str(), BPF_MAP_TYPE_HASH);
    if (!map.erase(&index, sizeof(index)))
    {
        std::cerr << "Update failed\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
#endif // ENABLE_HF_CHECK

int main(int argc, char* argv[])
{
    if (argc >= 2)
    {
        try {
            if (std::strcmp(argv[1], "attach") == 0)
                return attachBr(argc - 2, argv + 2);
            else if (std::strcmp(argv[1], "detach") == 0)
                return detachBr(argc - 2, argv + 2);
            else if (std::strcmp(argv[1], "watch") == 0)
                return watchBr(argc - 2, argv + 2);
        #ifdef ENABLE_HF_CHECK
            else if (std::strcmp(argv[1], "key") == 0)
            {
                if (argc >= 3)
                {
                    if (std::strcmp(argv[2], "add") == 0)
                        return addHopKey(argc - 3, argv + 3);
                    else if (std::strcmp(argv[2], "remove") == 0)
                        return removeHopKey(argc - 3, argv + 3);
                }
            }
        #endif
        }
        catch (std::exception &e) {
            std::cerr << "ERROR: " << e.what() << '\n';
            return EXIT_FAILURE;
        }
    }
    printUsage();
    return EXIT_FAILURE;
}
