#!/usr/bin/env python3
# Copyright (c) 2022 Lars-Christian Schulz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import socket
import subprocess
import time

import pyroute2
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from pr2modules.netlink.exceptions import NetlinkError
from pr2modules.netns import popns, pushns
from scapy.fields import IntField, SecondsIntField, XStrLenField
from scapy.layers.inet import UDP
from scapy.main import interact as scapy_interact
from scapy.packet import Packet, bind_layers


TEST_PORT = 6500

class AESCMAC(Packet):
    name = "AES-CMAC"

    fields_desc = [
        XStrLenField("cmac", default=16*b"\x00", length_from=lambda pkt: 16),
        SecondsIntField("time", default=0, use_nano=True),
        IntField("seq", default=0),
        XStrLenField("data", default=16*b"\x00", length_from=lambda pkt: 16)
    ]

    def calc_cmac(self, key: bytes) -> bytes:
        c = cmac.CMAC(algorithms.AES(key))
        c.update(self.data)
        return c.finalize()

bind_layers(UDP, AESCMAC, dport=TEST_PORT)


class Fixture:
    def __init__(self):
        self.ns = None
        self.veth0 = self.veth1 = None

        self.ns_name = "xdp_test"
        self.veth0_name = "veth0"
        self.veth0_ip = "10.1.0.1"
        self.veth0_mask = 24
        self.veth1_name = "veth1"
        self.veth1_ip = "10.1.0.2"
        self.veth1_mask = 24

    def create(self):
        ipr = pyroute2.IPRoute()
        self.ns = pyroute2.NetNS("xdp_test")

        reuse_veth = False
        try:
            ipr.link("add", ifname=self.veth0_name, kind="veth", peer=self.veth1_name)
        except NetlinkError as e:
            if e.code == 17:
                print("Using existing veth pair")
                reuse_veth = True
            else:
                raise

        if reuse_veth:
            self.veth0 = ipr.link_lookup(ifname=self.veth0_name)[0]
            self.veth1 = self.ns.link_lookup(ifname=self.veth1_name)[0]

        else:
            self.veth0 = ipr.link_lookup(ifname=self.veth0_name)[0]
            self.veth1 = ipr.link_lookup(ifname=self.veth1_name)[0]

            ipr.addr("add", index=self.veth0, address=self.veth0_ip, mask=self.veth0_mask)
            ipr.link("set", index=self.veth0, state="up")

            ipr.link("set", index=self.veth1, net_ns_fd=self.ns_name)
            self.ns.addr("add", index=self.veth1, address=self.veth1_ip, mask=self.veth1_mask)
            self.ns.link("set", index=self.veth1, state="up")

            # Disable protocol offload
            subprocess.run([
                "ethtool", "--offload", self.veth0_name, "rx", "off", "tx", "off"
            ], check=True, capture_output=True)
            subprocess.run([
                "ip", "netns", "exec", self.ns_name,
                "ethtool", "--offload", self.veth1_name, "rx", "off", "tx", "off"
            ], check=True, capture_output=True)

    def destroy(self):
        if self.ns:
            self.ns.close()
            self.ns.remove()
            self.ns = self.veth0 = self.veth1 = None


def test(fixture, receiver, sender):
    dest = (fixture.veth0_ip, TEST_PORT)
    src = None
    sent_msg = recv_msg = None

    aes_key = b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c"
    test_cases = [
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\x6b\xc1\xbe\xe2\x2e\x40\x9f\x96\xe9\x3d\x7e\x11\x73\x93\x17\x2a",
        b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff",
    ]

    failed = 0
    for seq, data in enumerate(test_cases):
        print(f"\n### TEST CASE {seq} ###")

        err = False
        p1 = AESCMAC(seq=seq, data=data)

        # Send packet on one interface
        print("Sent:")
        p1.show()
        sent_msg = bytes(p1)
        sender.sendto(sent_msg, dest)

        # Receive on the other interface
        while True:
            recv_msg, src = receiver.recvfrom(4096)
            if src[0] == fixture.veth1_ip:
                break
        if len(recv_msg) != len(sent_msg):
            print("Received massage has incorrect length!")
            err = True
        p2 = AESCMAC(recv_msg)
        print("Received :")
        p2.show()

        # Check CMAC
        expected = p2.calc_cmac(aes_key)
        if p2.cmac != expected:
            print(f"Incorrect MAC! Should be 0x{expected.hex()}")
            err = True

        if err:
            failed += 1

    if failed > 0:
        print(f"\nFAILED: {failed} test cases failed")
    else:
        print("\nPASSED")


def main():
    parser = argparse.ArgumentParser(description="Test the XDP program")
    parser.add_argument("-i", "--interactive", action='store_true',
        help="Drop into an interactive scapy shell")
    parser.add_argument("-k", "--keep", action='store_true',
        help="Do not delete the network namespaces and virtual interfaces after running the tests")
    args = parser.parse_args()

    # Create veth pair
    fixture = Fixture()
    fixture.create()

    xdp = receiver = sender = None
    try:
        # Load XDP program
        xdp = subprocess.Popen(
            ["build/xdp_loader", "build/xdp_combined.o", fixture.veth0_name],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8")
        time.sleep(0.1) # FIXME: Proper synchronization
        if xdp.poll():
            print("XDP Loader has failed:")
            print(xdp.communicate()[0])

        # Open UDP sockets
        receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        receiver.bind((fixture.veth0_ip, TEST_PORT))
        pushns(fixture.ns_name)
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        popns()

        if args.interactive:
            scapy_interact(argv=[], mydict=dict(globals(), **locals()))
        else:
            test(fixture, receiver, sender)

    finally:
        if receiver:
            receiver.close()
        if sender:
            sender.close()
        if xdp:
            xdp.terminate()
            print("XDP Loader returned:", xdp.wait())
        if not args.keep:
            fixture.destroy()


if __name__ == "__main__":
    main()
