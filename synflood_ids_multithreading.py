import scapy.all as scp
from datetime import datetime
import threading

timeout = 2  # seconds


# temporary (until we integrate flag check in sniff())
def check_flag(packet, flag):
    # try and except because some tcp packets dont have flags
    try:
        if packet.getlayer(scp.TCP).flags == flag:
            return packet
    except:
        pass

    return None


def start_syn_ack_thread(packet):

    # checking if packet is a SYN flag tcp
    # TODO: include this filter in the filter of the lower sniff() function
    if not check_flag(packet, "S"):
        return

    # print("SYN found (1)")

    thread = threading.Thread(target=find_syn_ack_thread, args=(packet,))
    thread.start()


# executed in thread (1)
def find_syn_ack_thread(packet):
    packet_src = packet.getlayer(scp.IP).src
    packet_dst = packet.getlayer(scp.IP).dst

    # sniff to find SYN/ACK
    packets = scp.sniff(
        filter="tcp and src host " + packet_dst + " and dst host " + packet_src,
        prn=find_syn_ack,
        timeout=timeout,
    )

    # TEMPORARY: can remove after adding flag filters to sniff
    # checking to see if theres any SYN/ACK after timeout
    syn_ack_packet_found = False
    for packet in packets:
        if check_flag(packet, "SA"):
            syn_ack_packet_found = True

    if not syn_ack_packet_found:
        print("No SYN/ACK packet found after timeout")

    # TODO: detect for a SYN attack


# executed in thread (1)
def find_syn_ack(packet):
    # checking if packet is a SYN/ACK flag tcp
    if not check_flag(packet, "SA"):
        return

    # print(datetime.now(), "SYN/ACK found (2)")

    # TODO: look for ACK package
    thread = threading.Thread(target=find_ack_thread, args=(packet,))
    thread.start()


def find_ack_thread(packet):
    packet_src = packet.getlayer(scp.IP).src
    packet_dst = packet.getlayer(scp.IP).dst

    # sniff to find SYN/ACK
    packets = scp.sniff(
        filter="tcp and src host " + packet_src + " and dst host " + packet_dst,
        prn=find_ack,
        timeout=timeout,
    )

    # TEMPORARY: can remove after adding flag filters to sniff
    # checking to see if theres any SYN/ACK after timeout
    syn_ack_packet_found = False
    for packet in packets:
        if check_flag(packet, "A"):
            syn_ack_packet_found = True

    if not syn_ack_packet_found:
        print("No ACK packet found after timeout")

    # TODO: detect for a SYN attack


def find_ack(packet):
    if not check_flag(packet, "A"):
        return

    print(datetime.now(), "ACK found (3)")


scp.sniff(prn=start_syn_ack_thread, filter="tcp")
