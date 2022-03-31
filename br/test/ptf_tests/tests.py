import base64

import ptf
import ptf.ptfutils
import pyroute2
from ptf.base_tests import BaseTest
from ptf.testutils import group, send_packet
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw, bind_layers
from scapy_scion.layers.scion import SCION, HopField, InfoField, SCIONPath

from common.port_stats import Counter, PortStatsMap
from common.util import verify_scion_packet


class TestTopology1(BaseTest):
    """Base class for tests using the topology defined in "test/single/setup.bash" and
    "test/multi/setup.bash".
    """
    mac_keys = {
        "1-ff00:0:1": base64.b64encode(8*b"11"),
        "1-ff00:0:2": base64.b64encode(8*b"22"),
        "1-ff00:0:3": base64.b64encode(8*b"33"),
        "1-ff00:0:4": base64.b64encode(8*b"44"),
        "1-ff00:0:5": base64.b64encode(8*b"55"),
        "1-ff00:0:6": base64.b64encode(8*b"66"),
        "1-ff00:0:7": base64.b64encode(8*b"77"),
        "1-ff00:0:8": base64.b64encode(8*b"88"),
        "1-ff00:0:9": base64.b64encode(8*b"99"),
    }
    payload = UDP(sport=6500, dport=6500)/Raw("TEST")
    map_paths = [
        b"/sys/fs/bpf/br1-ff00_0_1-1/",
        b"/sys/fs/bpf/br1-ff00_0_1-2/",
        b"/sys/fs/bpf/br1-ff00_0_1-3/"
    ]
    veth_index = {}

    def setUp(self):
        BaseTest.setUp(self)

        self.dataplane = ptf.dataplane_instance
        bind_layers(UDP, SCION, dport=50000)

        # Initialize interface name to index mapping
        if len(self.veth_index) == 0:
            with pyroute2.NetNS("sw0") as sw0:
                for veth in [f"veth{n}" for n in [1, 3, 5, 7]]:
                    self.veth_index[veth] = sw0.link_lookup(ifname=veth)[0]

        # Open BR port statistics
        self.port_stats = PortStatsMap(self.map_paths[0] + b"port_stats_map", ports=[
            # External interfaces
            self.veth_index["veth1"], # AS interface 1
            self.veth_index["veth3"], # AS interface 2
            # Internal interfaces
            self.veth_index["veth5"],
            self.veth_index["veth7"]
        ])

    def tearDown(self):
        self.port_stats.close()
        return BaseTest.tearDown(self)

    def _init_single_seg_path(self, ing_ifid, egr_ifid, path, expect_as_ingress, expect_as_egress):
        src_as = "1-ff00:0:{}".format(str(ing_ifid + 1))
        dst_as = "1-ff00:0:{}".format(str(egr_ifid + 1))

        path.init_path(keys=[
            self.mac_keys[src_as],
            self.mac_keys["1-ff00:0:1"],
            self.mac_keys[dst_as],
        ], seeds=[bytes(0xffff)])
        path.egress(self.mac_keys[src_as])
        path = SCIONPath(bytes(path))
        expected = path.copy()

        if expect_as_ingress:
            expected.ingress(self.mac_keys["1-ff00:0:1"])
        if expect_as_egress:
            expected.egress(self.mac_keys["1-ff00:0:1"])

        return path, expected

    def create_pkt_down_seg(self,
        ing_ifid, egr_ifid, ing_enc, egr_enc,
        expect_as_ingress=True, expect_as_egress=True):
        """Construct a SCION UDP packet with a path containing a down-segment.
        """
        path = SCIONPath(
            Seg0Len=3, Seg1Len=0, Seg2Len=0,
            InfoFields=[
                InfoField(Flags="C")
            ],
            HopFields=[
                HopField(ConsIngress=0, ConsEgress=1),
                HopField(ConsIngress=ing_ifid, ConsEgress=egr_ifid),
                HopField(ConsIngress=1, ConsEgress=0),
            ]
        )
        path, expected = self._init_single_seg_path(
            ing_ifid, egr_ifid, path, expect_as_ingress, expect_as_egress
        )
        return (
            Ether(bytes(ing_enc/SCION(Path=path)/self.payload)),
            Ether(bytes(egr_enc/SCION(Path=expected)/self.payload))
        )


    def create_pkt_up_seg(self,
        ing_ifid, egr_ifid, ing_enc, egr_enc,
        expect_as_ingress=True, expect_as_egress=True
        ):
        """Construct a SCION UDP packet with a path containing an up-segment.
        """
        path = SCIONPath(
            Seg0Len=3, Seg1Len=0, Seg2Len=0,
            InfoFields=[
                InfoField()
            ],
            HopFields=[
                HopField(ConsIngress=1, ConsEgress=0),
                HopField(ConsIngress=egr_ifid, ConsEgress=ing_ifid),
                HopField(ConsIngress=0, ConsEgress=1),
            ]
        )
        path, expected = self._init_single_seg_path(
            ing_ifid, egr_ifid, path, expect_as_ingress, expect_as_egress
        )
        return (
            Ether(bytes(ing_enc/SCION(Path=path)/self.payload)),
            Ether(bytes(egr_enc/SCION(Path=expected)/self.payload))
        )

    def create_pkt_core_seg(self,
        ing_ifid, egr_ifid, ing_enc, egr_enc,
        expect_as_ingress=True, expect_as_egress=True
        ):
        """Construct a SCION UDP packet with a path containing a core-segment.
        """
        path = SCIONPath(
            Seg0Len=3, Seg1Len=0, Seg2Len=0,
            InfoFields=[
                InfoField()
            ],
            HopFields=[
                HopField(ConsIngress=1, ConsEgress=0),
                HopField(ConsIngress=egr_ifid, ConsEgress=ing_ifid),
                HopField(ConsIngress=0, ConsEgress=1),
            ]
        )
        path, expected = self._init_single_seg_path(
            ing_ifid, egr_ifid, path, expect_as_ingress, expect_as_egress
        )
        return (
            Ether(bytes(ing_enc/SCION(Path=path)/self.payload)),
            Ether(bytes(egr_enc/SCION(Path=expected)/self.payload))
        )

    def create_pkt_seg_switch(self,
        ing_ifid, egr_ifid, ing_enc, egr_enc,
        expect_as_ingress=True, expect_as_egress=True):
        """Construct a SCION UDP packet with a path containing an up- and a down-segment. The
        border router under test is expected to switch from one segment to the next.
        """
        source_as = "1-ff00:0:{}".format(str(ing_ifid + 1))
        destination_as = "1-ff00:0:{}".format(str(egr_ifid + 1))
        path = SCIONPath(
            Seg0Len=2, Seg1Len=3, Seg2Len=0,
            InfoFields=[
                InfoField(),
                InfoField(Flags="C")
            ],
            HopFields=[
                # Up-segment
                HopField(ConsIngress=1, ConsEgress=0),
                HopField(ConsIngress=0, ConsEgress=ing_ifid),
                # Down-segment
                HopField(ConsIngress=0, ConsEgress=egr_ifid),
                HopField(ConsIngress=1, ConsEgress=2),
                HopField(ConsIngress=1, ConsEgress=0),
            ]
        )
        path.init_path(keys=[
            self.mac_keys[source_as],
            self.mac_keys["1-ff00:0:1"],
            self.mac_keys["1-ff00:0:1"],
            self.mac_keys[destination_as],
            self.mac_keys["1-ff00:0:8"],
        ], seeds=[bytes(0xffff)])
        path.egress(self.mac_keys[source_as])
        path = SCIONPath(bytes(path))
        expected = path.copy()
        if expect_as_ingress:
            expected.ingress(self.mac_keys["1-ff00:0:1"])
        if expect_as_egress:
            expected.egress(self.mac_keys["1-ff00:0:1"])
        return (
            Ether(bytes(ing_enc/SCION(Path=path)/self.payload)),
            Ether(bytes(egr_enc/SCION(Path=expected)/self.payload))
        )

    def test_down_segment(self, ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc):
        pkt, expected = self.create_pkt_down_seg(ing_ifid, egr_ifid, ing_enc, egr_enc)
        before = self.port_stats.get_counter_total(cnt_port, Counter.SCION_FORWARD, sync=True)
        send_packet(self, ing_port, pkt)
        verify_scion_packet(self, expected, egr_port)
        after = self.port_stats.get_counter_total(cnt_port, Counter.SCION_FORWARD, sync=True)
        self.assertEqual((before[0] + len(pkt), before[1] + 1), after)

    def test_up_segment(self, ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc):
        pkt, expected = self.create_pkt_up_seg(ing_ifid, egr_ifid, ing_enc, egr_enc)
        before = self.port_stats.get_counter_total(cnt_port, Counter.SCION_FORWARD, sync=True)
        send_packet(self, ing_port, pkt)
        verify_scion_packet(self, expected, egr_port)
        after = self.port_stats.get_counter_total(cnt_port, Counter.SCION_FORWARD, sync=True)
        self.assertEqual((before[0] + len(pkt), before[1] + 1), after)

    def test_core_segment(self, ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc):
        pkt, expected = self.create_pkt_core_seg(ing_ifid, egr_ifid, ing_enc, egr_enc)
        before = self.port_stats.get_counter_total(cnt_port, Counter.SCION_FORWARD, sync=True)
        send_packet(self, ing_port, pkt)
        verify_scion_packet(self, expected, egr_port)
        after = self.port_stats.get_counter_total(cnt_port, Counter.SCION_FORWARD, sync=True)
        self.assertEqual((before[0] + len(pkt), before[1] + 1), after)

    def test_seg_switch(self, ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc):
        """Up- and Down-segment with segment switch at core AS"""
        pkt, expected = self.create_pkt_seg_switch(ing_ifid, egr_ifid, ing_enc, egr_enc)
        before = self.port_stats.get_counter_total(cnt_port, Counter.SCION_FORWARD, sync=True)
        send_packet(self, ing_port, pkt)
        verify_scion_packet(self, expected, egr_port)
        after = self.port_stats.get_counter_total(cnt_port, Counter.SCION_FORWARD, sync=True)
        self.assertEqual((before[0] + len(pkt), before[1] + 1), after)


@group("single_device")
@group("multi_device")
class DirectlyAttachedTest(TestTopology1):
    """Test forwarding between two ASes directly attached to the border router under test.
    """
    def runTest(self):
        ing_ifid = 1
        egr_ifid = 2
        ing_enc = Ether(src="02:00:00:00:00:00", dst="02:00:00:00:00:01") \
            / IP(src="10.1.1.1", dst="10.1.1.2") \
            / UDP(sport=50000, dport=50000)
        egr_enc = Ether(src="02:00:00:00:00:03", dst="02:00:00:00:00:02") \
            / IP(src="10.1.2.2", dst="10.1.2.1") \
            / UDP(sport=50000, dport=50000)
        ing_port = (0, ing_ifid)
        egr_port = (0, egr_ifid)
        cnt_port = self.veth_index["veth1"]

        self.test_down_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_up_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_core_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_seg_switch(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)


@group("multi_device")
class ForwardToSiblingTest(TestTopology1):
    """Test forwarding of packets to a sibling border router.
    """
    def runTest(self):
        ing_ifid = 1
        egr_ifid = 3
        ing_enc = Ether(src="02:00:00:00:00:00", dst="02:00:00:00:00:01") \
            / IP(src="10.1.1.1", dst="10.1.1.2") \
            / UDP(sport=50000, dport=50000)
        egr_enc = Ether(src="02:00:00:00:00:09", dst="02:00:00:00:00:08") \
            / IP(src="10.1.3.2", dst="10.1.3.1") \
            / UDP(sport=50000, dport=50000)
        ing_port = (0, ing_ifid)
        egr_port = (1, egr_ifid)
        cnt_port = self.veth_index["veth1"]

        self.test_down_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_up_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_core_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_seg_switch(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)


@group("multi_device")
class IpForwardTest(TestTopology1):
    """Test forwarding between two sibling border routers.
    """
    def runTest(self):
        ing_ifid = 4
        egr_ifid = 6
        ing_enc = Ether(src="02:00:00:00:00:0a", dst="02:00:00:00:00:0b") \
            / IP(src="10.1.4.1", dst="10.1.4.2") \
            / UDP(sport=50000, dport=50000)
        egr_enc = Ether(src="02:00:00:00:00:0f", dst="02:00:00:00:00:0e") \
            / IP(src="10.1.6.2", dst="10.1.6.1") \
            / UDP(sport=50000, dport=50000)
        ing_port = (1, ing_ifid)
        egr_port = (2, egr_ifid)
        cnt_port = self.veth_index["veth5"]

        self.test_down_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_up_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_core_segment(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
        self.test_seg_switch(ing_port, egr_port, cnt_port, ing_ifid, egr_ifid, ing_enc, egr_enc)
