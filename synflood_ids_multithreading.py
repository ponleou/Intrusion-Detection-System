import scapy.all as scp
from datetime import datetime
import threading

timeout = 2  # seconds


def check_flag(packet, flag):
    if packet.getlayer(scp.TCP).flags == flag:
        return packet

    return None


def start_syn_ack_thread(packet):

    # checking if packet is a SYN flag tcp
    # TODO: include this filter in the filter of the lower sniff() function
    if not check_flag(packet, "S"):
        return

    threading.Thread(target=await_syn_ack, args=(packet,)).start()


def await_syn_ack(packet):
    packet_src = packet.getlayer(scp.IP).src
    packet_dst = packet.getlayer(scp.IP).dst

    scp.sniff(filter="tcp", prn=find_syn_ack)


def find_syn_ack(packet):
    pass


scp.sniff(prn=start_syn_ack_thread, filter="tcp")
