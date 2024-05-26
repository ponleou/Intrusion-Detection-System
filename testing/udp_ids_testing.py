import scapy.all as scp
import threading

# UDP flood detector
udp_timeout = 10
udp_threshold = 100

udp_time_check = 2

interaction_icmp_error = {}


def reset_icmp_error():
    global interaction_icmp_error
    interaction_icmp_error = {}


def udp_detector_threader(packet):
    try:
        if not packet.getlayer(scp.IP).proto == 17:  # UDP protocol's number is 17
            return
    except:
        return

    src_ip = packet.getlayer(scp.IP).src
    dst_ip = packet.getlayer(scp.IP).dst
    src_port = packet.getlayer(scp.UDP).sport
    dst_port = packet.getlayer(scp.UDP).dport
    src_mac_ad = packet.src
    dst_mac_ad = packet.dst

    thread = threading.Thread(
        target=find_icmp_pkt_thread,
        args=(src_ip, dst_ip, src_port, dst_port, src_mac_ad, dst_mac_ad),
    )
    thread.start()


def find_icmp_pkt_thread(src_ip, dst_ip, src_port, dst_port, src_mac_ad, dst_mac_ad):
    scp.sniff(
        filter="icmp and dst host " + src_ip,
        prn=lambda x: icmp_pkt_checker(
            x, src_ip, dst_ip, src_port, dst_port, src_mac_ad, dst_mac_ad
        ),
        timeout=udp_timeout,
    )


def icmp_pkt_checker(
    packet, src_ip, dst_ip, src_port, dst_port, src_mac_ad, dst_mac_ad
):
    try:
        if not packet.getlayer(scp.IP).proto == 1:
            return
    except:
        return

    # ICMP type 3 is for "distination unreachable"
    try:
        if not packet.getlayer(scp.ICMP).type == 3:
            return
    except:
        return

    # ICMP code 3 is for "port is unreachable"
    try:
        if not packet.getlayer(scp.ICMP).code == 3:
            return
    except:
        return

    if (
        not packet.getlayer(scp.IPerror).src == src_ip
        and not packet.getlayer(scp.IPerror).dst == dst_ip
    ):
        return

    if (
        packet.getlayer(scp.UDPerror).sport == src_port
        and packet.getlayer(scp.UDPerror).dport == dst_port
    ):

        interaction_name = src_mac_ad + " and " + dst_mac_ad

        if interaction_name not in interaction_icmp_error:
            interaction_icmp_error[interaction_name] = 0

        interaction_icmp_error[interaction_name] += 1

    print(interaction_icmp_error)


def udpflood_detector():
    while True:
        time.sleep(udp_time_check)

        for interaction_name in interaction_icmp_error:
            mac_ad = interaction_name.split(" and ")

            if verbose >= 1:
                logging(
                    str(interaction_icmp_error[interaction_name])
                    + "ICMP Destination error (Port not found) packets sent from "
                    + mac_ad[1]
                    + " to "
                    + mac_ad[0]
                )

            if interaction_icmp_error[interaction_name] >= udp_threshold:
                if verbose >= 0:
                    logging(
                        "WARNING: UDP flood detected by "
                        + mac_ad[0]
                        + " targeting "
                        + mac_ad[1]
                    )
        reset_icmp_error()


udpflood_detector_thread = threading.Thread(target=udpflood_detector)
