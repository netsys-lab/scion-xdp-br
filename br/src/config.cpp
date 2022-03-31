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

#include "config.hpp"

#include <sys/types.h>
#include <ifaddrs.h>

#include "tomlplusplus/toml.hpp"
#include <boost/json.hpp>
#include <boost/lexical_cast.hpp>

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <unordered_map>

using std::uint16_t;
using std::uint32_t;
using std::uint64_t;


////////////////////////
// Internal Functions //
////////////////////////

namespace {

/// \brief Load JSON from an input stream.
boost::json::value parseJson(std::istream &stream)
{
    boost::json::stream_parser parser;
    std::array<char, 4096> buffer;
    while (stream)
    {
        stream.read(buffer.data(), buffer.size());
        parser.write(buffer.data(), stream.gcount());
    }
    parser.finish();
    return parser.release();
}

/// \brief Parse an endpoint address consisting of IP and (UDP) port.
/// \details The IP address can either be a decimal IPv4 address in dotted notation or a
/// hexadecimal IPv6 address.
/// - IPv4: "127.0.0.1:50000"
/// - IPv6: "[::1]:50000"
UdpEp parseUdpEp(const boost::json::string &str)
{
    using boost::asio::ip::make_address;

    // Split at last colon
    auto colonPos = str.find_last_of(":");
    if (colonPos == boost::json::string::npos)
        throw std::invalid_argument("Invalid underlay address");
    auto ipStr = str.subview(0, colonPos);
    auto portStr = str.subview(colonPos + 1);

    // Remove brackets from IPv6 address
    if (ipStr.starts_with('['))
        ipStr.remove_prefix(1);
    if (ipStr.ends_with(']'))
        ipStr.remove_suffix(1);

    return UdpEp{
        .ip = make_address(ipStr.to_string()),
        .port = boost::lexical_cast<std::uint16_t>(portStr),
    };
}

/// \brief Parse a SCION topology declaration ("topology.json").
/// \param[in] topo Topology JSON
/// \param[in] self Id of the border router itself as it appears in the topology file
///            (e.g. "br1-ff00_0_1-1")
/// \param[out] Interfaces discovered from the topology file are added to this struct.
/// \exception Throws std::invalid_argument or std::out_of_range if parsing errors occur.
void parseTopology(const boost::json::value &topo, const std::string &self, BrInterfaces &brIf)
{
    auto brs = topo.as_object().at("border_routers").as_object();
    for (const auto &br : brs)
    {
        auto ifaces = br.value().as_object().at("interfaces").as_object();
        if (br.key() == self)
        {
            for (const auto &iface : ifaces)
            {
                auto underlay = iface.value().as_object().at("underlay").as_object();
                brIf.external.emplace_back(ExternalIface{
                    .scionIfId = boost::lexical_cast<std::uint32_t>(iface.key()),
                    .local = parseUdpEp(underlay.at("public").as_string()),
                    .remote = parseUdpEp(underlay.at("remote").as_string())
                });
            }
        }
        else
        {
            auto destBr = parseUdpEp(br.value().as_object().at("internal_addr").as_string());
            for (const auto &iface : ifaces)
            {
                brIf.sibling.emplace_back(SiblingIface{
                    .scionIfId = boost::lexical_cast<std::uint32_t>(iface.key()),
                    .destBr = destBr
                });
            }
        }
    }
}

/// \brief Read the internal interface table from the main configuration file.
/// \param[in] confTable The configuration file/table.
/// \param[out] intIfs Internal interfaces are added to this vector.
/// \exception Throws std::invalid_argument or std::out_of_range if parsing errors occur.
void parseInternalIfaces(const toml::table &confTable, std::vector<InternalIface> &intIfs)
{
    using boost::asio::ip::make_address;

    auto ifaces = confTable["internal_interfaces"];
    if (!ifaces.is_array_of_tables()) throw std::invalid_argument(
        "Configuration item 'internal_interfaces' is missing or has an invalid value.");

    for (const auto &iface : *ifaces.as_array())
    {
        auto ip = (*iface.as_table())["ip"].value<std::string_view>();
        if (!ip) throw std::invalid_argument("Internal interface is missing an IP address.");
        auto port = (*iface.as_table())["port"].value<uint16_t>();
        if (!port) throw std::invalid_argument("Internal interface is missing the UDP port.");

        intIfs.emplace_back(InternalIface{
            .local = {
                .ip = make_address(*ip),
                .port = *port
            }
        });
    }
}

using IfMap = std::unordered_map<boost::asio::ip::address, std::string>;

/// \brief Returns a mapping from IP address to interface name for all Ethernet interfaces in the
/// system (or network namespace).
IfMap getIfAddr()
{
    using boost::asio::ip::address;
    using boost::asio::ip::address_v6;
    using boost::asio::ip::make_address_v4;
    using boost::asio::ip::make_address_v6;

    ifaddrs *ifaddr = nullptr;
    if (getifaddrs(&ifaddr))
        throw std::runtime_error("getifaddrs failed");
    auto deleter = [](ifaddrs *p) { freeifaddrs(p); };
    std::unique_ptr<ifaddrs, decltype(deleter)> firstIfaddr(ifaddr, deleter);

    std::unordered_map<boost::asio::ip::address, std::string> ifMap;
    ifMap.reserve(128);

    for (;ifaddr; ifaddr = ifaddr->ifa_next)
    {
        address ip;
        if (ifaddr->ifa_addr->sa_family == AF_INET)
        {
            auto sockaddr = reinterpret_cast<sockaddr_in*>(ifaddr->ifa_addr);
            ip = make_address_v4(ntohl(sockaddr->sin_addr.s_addr));
        }
        else if (ifaddr->ifa_addr->sa_family == AF_INET6)
        {
            auto sockaddr = reinterpret_cast<sockaddr_in6*>(ifaddr->ifa_addr);
            auto p = sockaddr->sin6_addr.__in6_u.__u6_addr8;
            address_v6::bytes_type addr;
            std::copy(p, p + addr.size(), addr.data());
            ip = make_address_v6(addr, sockaddr->sin6_scope_id);
        }
        ifMap[ip] = std::string(ifaddr->ifa_name);
    }

    return ifMap;
}

} // namespace

////////////////
// loadConfig //
////////////////

std::optional<BrConfig> loadConfig(const char *configFile)
{
    BrConfig config;
    auto ifMap = getIfAddr();

    // Parse configuration file
    toml::table confTable;
    try {
        confTable = toml::parse_file(configFile);
    }
    catch (toml::parse_error &e) {
        std::cerr << "Parsing configuration failed:\n" << e << "\n";
        return std::nullopt;
    }

    // Get BR name
    auto self = confTable["self"].value<std::string_view>();
    if (!self)
    {
        std::cerr << "Configuration item 'self' is missing or has an invalid value.\n";
        return std::nullopt;
    }
    config.self = *self;

    // Get path to topology.json
    auto topoFile = confTable["topology"].value<std::string>();
    if (!topoFile)
    {
        std::cerr << "Configuration item 'topology' is missing or has an invalid value.\n";
        return std::nullopt;
    }

    // Parse topology file
    std::ifstream topoJson(*topoFile);
    if (!topoJson.is_open())
    {
        std::cerr << "File not found: " << *topoFile << '\n';
        return std::nullopt;
    }
    try {
        parseTopology(parseJson(topoJson), config.self, config.ifs);
    }
    catch (std::exception &e) {
        std::cerr << "Parsing topology file failed:\n" << e.what() << '\n';
        return std::nullopt;
    }

    // Get IPs and ports of internal interfaces
    try {
        parseInternalIfaces(confTable, config.ifs.internal);
    }
    catch (std::exception &e) {
        std::cerr << e.what() << '\n';
        return std::nullopt;
    }

    // Find Ethernet interfaces belonging to SCION underlay UDP endpoints
    for (auto &iface : config.ifs.external)
    {
        auto iter = ifMap.find(iface.local.ip);
        if (iter != ifMap.end())
            iface.ifname = iter->second;
        else
        {
            std::cerr
                << "WARNING: No interface has IP " << iface.local.ip << '\n'
                << "         Cannot forward packets to IFID " << iface.scionIfId << '\n';
        }
    }
    for (auto &iface : config.ifs.internal)
    {
        auto iter = ifMap.find(iface.local.ip);
        if (iter != ifMap.end())
            iface.ifname = iter->second;
        else
        {
            std::cerr << "WARNING: No interface has IP " << iface.local.ip << '\n';
        }
    }

    return config;
}

//////////////
// Printing //
//////////////

std::ostream& operator<<(std::ostream &stream, const UdpEp &brIf)
{
    stream << '[' << brIf.ip << "]:" << brIf.port;
    return stream;
}

std::ostream& operator<<(std::ostream &stream, const BrInterfaces &brIf)
{
    stream << "External interfaces:\n";
    for (const ExternalIface &iface : brIf.external)
    {
        stream << std::setw(5) << iface.scionIfId << ' ' << std::setw(6) << iface.ifname;
        stream << " local  " << iface.local;
        stream << "\n             remote " << iface.remote << '\n';
    }
    stream << "Sibling BR interfaces:\n";
    for (const SiblingIface &iface : brIf.sibling)
    {
        stream << std::setw(5) << iface.scionIfId;
        stream << " route to " << iface.destBr << '\n';
    }
    stream << "Internal interfaces:\n";
    for (const InternalIface &iface : brIf.internal)
    {
        stream << std::setw(6) << iface.ifname << ' ' << iface.local << '\n';
    }
    return stream;
}

std::ostream& operator<<(std::ostream &stream, const BrConfig &config)
{
    stream << "XDP Border Router " << config.self << '\n';
    stream << config.ifs;
    return stream;
}
