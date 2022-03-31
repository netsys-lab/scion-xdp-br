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
import time


def createMsg(seq):
    mac = 16*b'\x00'
    time = 0
    data = struct.pack("!QQ", seq, seq)
    return struct.pack("!16sII16s", mac, time, seq, data)


def send(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            seq = 0
            while True:
                for _ in range(10):
                    sock.sendto(createMsg(seq), (ip, port))
                    seq += 1
                time.sleep(2)
    except KeyboardInterrupt:
        print("Interrupted")


def main():
    parser = argparse.ArgumentParser(description="Send test packets.")
    parser.add_argument("ip", type=str)
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    print("Sending packets to {}:{}".format(args.ip, args.port))
    send(args.ip, args.port)


if __name__ == "__main__":
    main()
