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

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>


/// \brief IPv4 or IPv6 UDP Endpoint
struct UdpEp
{
    boost::asio::ip::address ip;
    std::uint16_t port;
};
std::ostream& operator<<(std::ostream &stream, const UdpEp &brIf);

/// \brief Describes an external interface of the border router, i.e., an interface to another AS.
struct ExternalIface
{
    std::uint32_t scionIfId; ///< SCION interface id
    std::string ifname;      ///< Name of the physical interface
    UdpEp local;             ///< Local endpoint of the underlay connection
    UdpEp remote;            ///< Remote endpoint of the underlay connection
};

/// \brief Describes a sibling interface, i.e., an external interface at another border router
/// belonging to the same AS.
struct SiblingIface
{
    std::uint32_t scionIfId; ///< SCION interface id
    UdpEp sibling;           ///< Underlay connection to sibling
};

/// \brief Describes an internal interface, i.e., an interface to the internal network.
struct InternalIface
{
    std::string ifname; ///< Name of the physical interface
    UdpEp local;        ///< Source address for SCION packets sent on the internal interface
};

/// \brief Lists of all border router interfaces.
struct BrInterfaces
{
    std::vector<ExternalIface> external;
    std::vector<SiblingIface> sibling;
    std::vector<InternalIface> internal;
};
std::ostream& operator<<(std::ostream &stream, const BrInterfaces &brIf);

/// \brief The border router root configuration object.
struct BrConfig
{
    std::string self;
    BrInterfaces ifs;
};
std::ostream& operator<<(std::ostream &stream, const BrConfig &config);

/// \brief Load the border router configuration file.
/// \return Empty, if loading the configuration failed.
std::optional<BrConfig> loadConfig(const char *configFile);
