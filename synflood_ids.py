import scapy.all as scp
from datetime import datetime


def tcp_filter(packets):
    filtered_packets = []

    for packet in packets:
        try:
            if packet.haslayer(scp.TCP):
                filtered_packets.append(packet)
        except:
            pass

    return filtered_packets


def syn_flag_packet(packets):
    filtered_packets = []

    for packet in packets:
        try:
            if packet.getlayer(scp.TCP).flags == "S":
                filtered_packets.append(packet)
        except:
            pass

    return filtered_packets


def syn_ack_flag_packet(packets):
    filtered_packets = []

    for packet in packets:
        try:
            if packet.getlayer(scp.TCP).flags == "SA":
                filtered_packets.append(packet)
        except:
            pass

    return filtered_packets


def ack_flag_packet(packets):
    filtered_packets = []

    for packet in packets:
        try:
            if packet.getlayer(scp.TCP).flags == "A":
                filtered_packets.append(packet)
        except:
            pass

    return filtered_packets


while True:
    packets = scp.sniff(count=100)

    tcp_packets = tcp_filter(packets)
    print(
        len(syn_flag_packet(tcp_packets)),
        len(syn_ack_flag_packet(tcp_packets)),
        len(ack_flag_packet(tcp_packets)),
    )
