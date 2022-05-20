import enum
import os
from ctypes import Structure, c_uint32, c_uint64
from typing import List, Optional

from libbpf import bpf, map


class Counter(enum.IntEnum):
    UNDEFINED = 0
    SCION_FORWARD = 1
    PARSE_ERROR = 2
    NOT_SCION = 3
    NOT_IMPLEMENTED = 4
    NO_INTERFACE = 5
    UNDERLAY_MISMATCH = 6
    ROUTER_ALERT = 7
    FIB_LKUP_DROP = 8
    FIB_LKUP_PASS = 9
    INVALID_HF = 10


class _port_stats(Structure):
    _fields_ = [
        ("verdict_bytes", c_uint64 * len(Counter)),
        ("verdict_packets", c_uint64 * len(Counter))
    ]


class PortStatsMap:
    """Class for reading the port statistics written by the BPF border router."""

    cpu_count = os.cpu_count()
    value_t = _port_stats * cpu_count

    def __init__(self, pin_path: bytes, ports: List[int]):
        self.map = map.Map(pin_path, bpf.BPF_MAP_TYPE_PERCPU_HASH)
        self.stats = {port: self.value_t() for port in ports}

    def close(self):
        self.map.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def sync(self, port: Optional[int] = None):
        """Fetch the current values from the map."""
        if port is None:
            for port, stats in self.stats.items():
                self.map.lookup(c_uint32(port), stats)
        else:
            self.map.lookup(c_uint32(port), self.stats[port])

    def get_counter_total(self, port: int, counter: Counter, sync: bool=False):
        """Get the sum of a counter over all CPUs.
        :param port: Interface index to get statistics from.
        :param counter: Which counter to retrieve.
        :param sync: Whether to get new values from the BPF map. If not set, the values read on the
                     last sync are returned.
        :return: Pair of bytes and packet count.
        """
        if sync:
            self.sync(port)
        total_bytes = 0
        total_packets = 0
        for cpu in range(self.cpu_count):
            total_bytes += self.stats[port][cpu].verdict_bytes[counter]
            total_packets += self.stats[port][cpu].verdict_packets[counter]
        return (total_bytes, total_packets)
