import scapy.all as scp
from datetime import datetime
import threading

timeout = 2  # seconds


# temporary (until we integrate flag check in sniff())
def check_flag(packet, flag):
    if packet.getlayer(scp.TCP).flags == flag:
        return packet

    return None


def start_syn_ack_thread(packet):

    # checking if packet is a SYN flag tcp
    # TODO: include this filter in the filter of the lower sniff() function
    if not check_flag(packet, "S"):
        return

    thread = threading.Thread(target=find_syn_ack_thread, args=(packet,))
    thread.start()


# executed in thread (1)
def find_syn_ack_thread(packet):
    packet_src = packet.getlayer(scp.IP).src
    packet_dst = packet.getlayer(scp.IP).dst

    # sniff to find SYN/ACK
    scp.sniff(
        filter="tcp and src host " + packet_dst + " and dst host " + packet_src,
        prn=find_syn_ack,
        timeout=timeout,
    )


# executed in thread (1)
def find_syn_ack(packet):
    # checking if packet is a SYN/ACK flag tcp
    if not check_flag(packet, "SA"):
        return

    print(datetime.now(), "SYN/ACK found")


scp.sniff(prn=start_syn_ack_thread, filter="tcp")
