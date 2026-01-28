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


def packet_flag_filter(packets, flag):
    filtered_packets = []

    for packet in packets:
        try:
            if packet.getlayer(scp.TCP).flags == flag:
                filtered_packets.append(packet)
        except:
            pass

    return filtered_packets


def find_packet(packets, ip_src, ip_dst):
    packet_found = None

    for packet in packets:
        packet_ip_layer = packet.getlayer(scp.IP)
        if packet_ip_layer.dst == ip_dst and packet_ip_layer.src == ip_src:
            packet_found = packet

    return packet_found


def tcp_handshake_checker(syn_packets, syn_ack_packets, ack_packets):
    if len(syn_packets) == 0:
        print(datetime.now(), "No SYN packet")
        return

    for syn_packet in syn_packets:

        syn_packet_src_ip = syn_packet.getlayer(scp.IP).src
        syn_packet_dst_ip = syn_packet.getlayer(scp.IP).dst

        cor_syn_ack_packet = find_packet(
            syn_ack_packets, syn_packet_dst_ip, syn_packet_src_ip
        )

        if cor_syn_ack_packet == None:
            print(
                datetime.now(),
                syn_packet_dst_ip
                + " failed to respond with SYN/ACK packet from "
                + syn_packet_src_ip
                + " SYN packet",
            )
            continue

        cor_ack_packet = find_packet(ack_packets, syn_packet_src_ip, syn_packet_dst_ip)

        if cor_ack_packet == None:
            print(
                datetime.now(),
                syn_packet_src_ip
                + " failed to respond with ACK packet from "
                + syn_packet_dst_ip
                + " SYN/ACK packet",
            )
            continue

        print(
            datetime.now(),
            "TCP handshake completed between "
            + syn_packet_src_ip
            + " and "
            + syn_packet_dst_ip,
        )


while True:
    packets = scp.sniff(count=100)

    tcp_packets = tcp_filter(packets)

    syn_packets = packet_flag_filter(tcp_packets, "S")
    syn_ack_packets = packet_flag_filter(tcp_packets, "SA")
    ack_packets = packet_flag_filter(tcp_packets, "A")

    tcp_handshake_checker(syn_packets, syn_ack_packets, ack_packets)
