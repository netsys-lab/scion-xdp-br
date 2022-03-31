#!/usr/bin/python3
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
import struct
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms


def printMsg(msg, key):
    mac, time, seq, data = struct.unpack("!16sII16s", msg)
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    expected = c.finalize()
    res = "OK" if mac == expected else "ERR"
    print(f"Seq {seq:>4}  0x{mac.hex()}  {time:>4}  0x{data.hex()}  {res}")


def listen(ip, port, key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((ip, port))
            while True:
                msg, addr = sock.recvfrom(4096)
                printMsg(msg, key)
    except KeyboardInterrupt:
        print("Interrupted")


def parseKey(raw: str) -> bytes:
    key = bytes.fromhex(raw)
    if len(key) != 16:
        raise ValueError("Invalid key size")
    return key


def main():
    parser = argparse.ArgumentParser(description="Listen for IPv4/UDP packets.")
    parser.add_argument("ip", type=str)
    parser.add_argument("port", type=int)
    parser.add_argument("--key", type=parseKey, required=False,
        default=b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c")
    args = parser.parse_args()
    print(f"Listening on {args.ip}:{args.port}")
    listen(args.ip, args.port, args.key)


if __name__ == "__main__":
    main()
