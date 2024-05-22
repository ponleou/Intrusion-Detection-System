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


def find_packet_with_dst_ip(packets, ip_dst):
    src_ip_packet_found = []

    for packet in packets:
        if packet.getlayer(scp.IP).dst == ip_dst:
            src_ip_packet_found.append(packet)

    return src_ip_packet_found


while True:
    packets = scp.sniff(count=1000)

    tcp_packets = tcp_filter(packets)

    syn_packets = syn_flag_packet(tcp_packets)
    syn_ack_packets = syn_ack_flag_packet(tcp_packets)
    ack_packets = ack_flag_packet(tcp_packets)

    if not (len(syn_flag_packet(tcp_packets)) == 0) and not (
        len(syn_ack_flag_packet(tcp_packets)) == 0
    ):
        dst_ip_packets = find_packet_with_dst_ip(
            ack_packets, syn_packets[0].getlayer(scp.IP).dst
        )
        print("SYN Packet:")
        print(syn_packets[0])
        print("SYN-ACK Packet:")
        print(syn_ack_packets[0])
        print("ACK Packet:")
        print(dst_ip_packets[0])
        print("..............")
