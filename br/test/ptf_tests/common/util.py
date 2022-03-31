import io

import ptf
import ptf.ptfutils
from ptf.testutils import dp_poll, port_to_tuple
from scapy.layers.inet import ICMP
from scapy.packet import Packet
from scapy_scion.layers.scion import SCION
from scapy_scion.utils import compare_layers


def compare_packets(packet1, packet2):
    """Compare two packets layer by layer."""
    layers1, layers2 = packet1.layers(), packet2.layers()
    for i, (layer1, layer2) in enumerate(zip(layers1, layers2)):
        if layer1 is not layer2:
            yield ("Layer", str(i), packet1[i].name, packet2[i].name)
            break
        for field, a, b in compare_layers(packet1[i], packet2[i]):
            yield (packet1[i].name, field, a, b)


def format_dp_result(dp_result) -> str:
    """Returns a string explaining why the test has failed."""
    # Make sure all recently received packets have been parsed.
    recent_pkts = []
    for pkt in dp_result.recent_packets:
        if isinstance(pkt, Packet):
            recent_pkts.append(pkt)
        else:
            recent_pkts.append(dp_result.expected_packet.__class__(pkt))

    # Try to find the most recently received SCION packet.
    received_packet = None
    for recent_pkt in recent_pkts:
        if not isinstance(recent_pkt, Packet):
            recent_pkt = dp_result.expected_packet.__class__(recent_pkt)
        if recent_pkt.haslayer(SCION) and not recent_pkt.haslayer(ICMP):
            received_packet = recent_pkt
            break

    # Print differences between the expected and received packet.
    if received_packet is not None:
        out = io.StringIO()
        print("Received {} packets, most recent {} packets:".format(
            dp_result.packet_count, len(recent_pkts)), file=out)
        for pkt in recent_pkts:
            print(pkt.summary(), file=out)
        print("Comparing to most recent SCION packet:", file=out)
        diff = list(compare_packets(dp_result.expected_packet, received_packet))
        if len(diff):
            print("{:<8} {:<25} {:>12} {:>12}".format("Layer", "Field", "Expected", "Actual"),
                file=out)
            for layer, field, a, b in diff:
                a = "None" if a is None else a
                b = "None" if b is None else b
                print("{:<8} {:<25} {:>12} {:>12}".format(layer, field, a, b), file=out)
        return out.getvalue()

    # If no packet is available for comparison, print the default message.
    return dp_result.format()


def verify_scion_packet(test, pkt, port_id, timeout=None):
    """Similar to ptf.testutils.verify_packet but attempts to print the difference between the
    expected and actually received packet in a table. Prints the same message as `verify_packet` if
    no (SCION) packet is received as all.
    """
    if not timeout:
        timeout = ptf.ptfutils.default_timeout
    device, port = port_to_tuple(port_id)
    result = dp_poll(test, device_number=device, port_number=port, timeout=timeout, exp_pkt=pkt)
    if isinstance(result, test.dataplane.PollFailure):
        test.fail(
            "Expected packet was not received on device {}, port {}.\n{}".format(
                device, port, format_dp_result(result)
            )
        )
