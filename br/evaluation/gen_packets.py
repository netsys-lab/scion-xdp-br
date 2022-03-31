#!/usr/bin/python

import argparse

from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw, bind_layers
from scapy.utils import wrpcap
from scapy_scion.layers.scion import SCION, HopField, InfoField, SCIONPath


parser = argparse.ArgumentParser(description="Generate SCION packets.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("output", help="Output pcap file")
parser.add_argument("-n", default=1000, help="Number of packet to generate")
parser.add_argument("--smac", default="02:00:00:00:00:00", help="Source MAC address")
parser.add_argument("--dmac", default="02:00:00:00:00:01", help="Destination MAC address")
parser.add_argument("--src", default="10.1.0.0", help="Source IP address")
parser.add_argument("--dst", default="10.1.0.1", help="Destination IP address")
args = parser.parse_args()


bind_layers(UDP, SCION, dport=50000)

keys=[
    b"MTExMTExMTExMTExMTExMQ==",
    b'MjIyMjIyMjIyMjIyMjIyMg==',
    b'MzMzMzMzMzMzMzMzMzMzMw=='
]
path = SCIONPath(
    Seg0Len=3, Seg1Len=0, Seg2Len=0,
    InfoFields=[
        InfoField(Flags="C")
    ],
    HopFields=[
        HopField(ConsIngress=0, ConsEgress=1),
        HopField(ConsIngress=1, ConsEgress=2),
        HopField(ConsIngress=1, ConsEgress=0),
    ]
)
path.init_path(keys=keys, seeds=[bytes(0xffff)])
path.egress(keys[0])

header = Ether(src=args.smac, dst=args.dmac) \
    / IP(src=args.src, dst=args.dst) \
    / UDP(sport=50000, dport=50000) \
    / SCION(Path=path) \
    / UDP(sport=60000, dport=9)

pkts = []
for i in range(args.n):
    pkts.append(header / Raw(i.to_bytes(4, byteorder='big')))
wrpcap(args.output, pkts)
