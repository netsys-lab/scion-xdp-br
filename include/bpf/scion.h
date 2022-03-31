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

#ifndef SCION_H_GUARD
#define SCION_H_GUARD

#include "types.h"


/* SCION common */

#define SC_PROTO_TCP 6
#define SC_PROTO_UDP 17
#define SC_PROTO_HBH 200
#define SC_PROTO_E2E_EXT 201
#define SC_PROTO_SCMP 202
#define SC_PROTO_BFD 203
#define SC_PROTO_EXP1 253
#define SC_PROTO_EXP2 254

#define SC_PATH_TYPE_EMPTY 0
#define SC_PATH_TYPE_SCION 1
#define SC_PATH_TYPE_ONE_HOP 2
#define SC_PATH_TYPE_EPIC 3
#define SC_PATH_TYPE_COLIBRI 4

#define SC_ADDR_TYPE_IP 0

#define SC_GET_VER(sc) (ntohl(sc->ver_qos_flow) >> 28)
#define SC_GET_QOS(sc) ((ntohl(sc->ver_qos_flow) >> 20) & 0xff)
#define SC_GET_FLOW(sc) (ntohl(sc->ver_qos_flow) & ((1 << 20ul) - 1))
#define SC_GET_DT(sc) (sc->haddr & 0x2)
#define SC_GET_DL(sc) ((sc->haddr >> 2) & 0x2)
#define SC_GET_ST(sc) ((sc->haddr >> 4) & 0x2)
#define SC_GET_SL(sc) ((sc->haddr >> 6) & 0x2)

struct __attribute__((packed)) scionhdr
{
    // Common header
    u32 ver_qos_flow; // (4 bit) header version (= 0)
                      // (8 bit) traffic class
                      // (20 bit) mandatory flow id,
    u8 next;          // next header type
    u8 len;           // header length in units of 4 bytes
    u16 payload;      // payload length in bytes
    u8 type;          // path type
    u8 haddr;         // (2 bit) destination address type
                      // (2 bit) destination address length
                      // (2 bit) source address type
                      // (2 bit) source address length
    u16 rsv;          // reserved

    // Address header
    u16 dest_isd;     // destination ISD
    u8 dest_as[6];    // destination AS
    u16 src_isd;      // source ISD
    u8 src_as[6];     // source AS
};

/* Standard SCION path */

// PathMeta Header
// (6 bit) number of hop field in path segment 2
// (6 bit) number of hop field in path segment 1
// (6 bit) number of hop field in path segment 0
// (6 bit) reserved
// (2 bit) index of current info field
// (6 bit) index of current hop field
// Macros ending in "_HOST" take an argument in host byte order.
#define PATH_GET_SEG2_HOST(path) (path & 0x3f)
#define PATH_GET_SEG1_HOST(path) ((path >> 6) & 0x3f)
#define PATH_GET_SEG0_HOST(path) ((path >> 12) & 0x3f)
#define PATH_GET_CURR_HF_HOST(path) ((path >> 24) & 0x3f)
#define PATH_GET_CURR_INF_HOST(path) ((path >> 30) & 0x03)

typedef u32 pathmetahdr;

#define INF_GET_CONS(info) (info->flags & 0x01)
#define INF_GET_PEER(info) (info->flags & 0x02)

struct __attribute__((packed)) infofield
{
    u8 flags;   // (1 bit) construction direction flag
                // (1 bit) peering path flag
                // (6 bit) reserved flags
    u8 rsv;     // reserved
    u16 seg_id; // SegID
    u32 ts;     // timestamp in Unix time
};

#define HF_GET_E_ALERT(hf) (hf->flags & 0x01)
#define HF_GET_I_ALERT(hf) (hf->flags & 0x02)

struct __attribute__((packed)) hopfield
{
    u8 flags;    // (1 bit) cons egress router alert
                 // (1 bit) cons ingress router alert
                 // (6 bit) reserved flags
    u8 exp;      // expiry time
    u16 ingress; // ingress interface in construction direction
    u16 egress;  // egress interface in construction direction
    u8 mac[6];   // message authentication code
};

struct __attribute__((packed)) macinput
{
    u16 null0;
    u16 beta;
    u32 ts;
    u8 null1;
    u8 exp;
    u16 ingress;
    u16 egress;
    u16 null2;
};

#endif // SCION_H_GUARD
