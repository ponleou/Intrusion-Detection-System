import scapy.all as scp
from datetime import datetime
import threading
import time


# Users can adjust these values
syn_time_check = 2  # seconds for each SYN flood check (lower time means less sensitive)
syn_threshold = 100  # minimum amount of missing packets in the period of syn_time_check to alert detection of SYN flood (Higher means less sensitive)

ps_threshold = 40  # minimum amount of unique accessed ports to alert port scan (higher means less sentitive)

udp_time_check = 5  # seconds for each UDP flood check (lower time means less sensitive)
udp_threshold = 100  # minimum amount of ICMP packets in response to UDP packets in the peroid of udp_time_check to alert UDP flood (higher means less sensitive)

verbose = 1  # log levels, from 0 to 3 (-1 for no logs)


# Users can adjust with caution (affects the effectiveness of the detection)
udp_info_time_reset = 30  # seconds, to reset the collected udp packets information
ps_time_check = 30  # seconds, change only if you know what you are doing
syn_timeout = 2  # seconds, change only if you know what you are doing


def logging(msg, file_name="ids_logs.txt"):
    with open(file_name, "a") as f:
        f.write(str(datetime.now()) + ": " + msg + "\n")


def syn_filter(packet):
    is_syn_flag = False

    try:
        if packet.getlayer(scp.TCP).flags == "S":
            is_syn_flag = True
    except:
        pass

    return is_syn_flag


def udp_filter(packet):
    is_udp_protocol = False

    try:
        if packet.haslayer(scp.UDP):
            is_udp_protocol = True
    except:
        pass

    return is_udp_protocol


def unique_port_organizer(
    packet, dictionary, src_or_dst_port=[True, True], src_or_dst_ip=[False, False]
):
    # src_or_dst_port can be changed to include or remove source port or destination port
    # src_or_dst_ip can be changed to include or remove source ip or destination ip (stays in the name of each array: interaction_name)
    packet_src = packet.src

    # some UDP packets dont have IP layer
    try:
        if src_or_dst_ip[0]:
            packet_src += "(" + packet.getlayer(scp.IP).src + ")"
    except:
        pass

    packet_dst = packet.dst
    try:
        if src_or_dst_ip[1]:
            packet_dst += "(" + packet.getlayer(scp.IP).dst + ")"
    except:
        pass

    interaction_name = packet_src + ", " + packet_dst

    if interaction_name not in dictionary:
        dictionary[interaction_name] = [[], []]
    # dictionary = {
    #   interaction_name = [
    #       [packet.sports...],
    #       [packet.dports...]
    #   ],...
    # }

    if src_or_dst_port[0]:
        if packet.sport not in dictionary[interaction_name][0]:
            dictionary[interaction_name][0].append(packet.sport)

    if src_or_dst_port[1]:
        if packet.dport not in dictionary[interaction_name][1]:
            dictionary[interaction_name][1].append(packet.dport)


# SYN FLOOD DETECTOR
interaction_missing_packets = {}


# function to run find_pkt_thread function in another thread
def syn_detector_threader(packet):

    is_syn_flag = syn_filter(packet)

    if not is_syn_flag:
        return

    src_ip = packet.getlayer(scp.IP).src
    dst_ip = packet.getlayer(scp.IP).dst
    packet_seq = packet.getlayer(scp.TCP).seq
    packet_flag = str(packet.getlayer(scp.TCP).flags)
    src_mac_ad = packet.src
    dst_mac_ad = packet.dst

    thread = threading.Thread(
        target=find_ack_pkt_thread,
        args=(packet_seq, src_ip, dst_ip, src_mac_ad, dst_mac_ad, packet_flag),
    )
    thread.start()


# function to find the correct acknowledgement number packet, will be ran in a seperate thread
def find_ack_pkt_thread(seq_num, src_ip, dst_ip, src_mac_ad, dst_mac_ad, packet_flag):

    packets = scp.sniff(
        filter="tcp and src host " + dst_ip + " and dst host " + src_ip,
        prn=lambda x: check_ack_number(x, seq_num),
        timeout=syn_timeout,
    )  # dst_ip is put for src_ip, and src_ip is put for dst_ip

    # double checking and handling missing acknowledgement packet
    packet_missing = check_missing_packet(packets, seq_num)
    if packet_missing:
        log_missing_packet(packet_flag, src_mac_ad, dst_mac_ad)


# checking if that packet is the acknowledgement to the syn packet
def check_ack_number(packet, seq_number):

    correct_ack_number = seq_number + 1
    try:
        packet_ack_number = packet.getlayer(scp.TCP).ack

        if packet_ack_number == correct_ack_number:
            pkt_flag_processor(packet)
    except:
        pass


# TEMPORARY: can remove after adding flag filters to sniff
def check_missing_packet(sniffed_packets, seq_number):

    correct_ack_number = seq_number + 1

    # if there has been an ack packet for a syn packet, this loop will return false
    # if the packet is missing, it will return true
    for packet in sniffed_packets:
        try:
            packet_ack_number = packet.getlayer(scp.TCP).ack

            if packet_ack_number == correct_ack_number:
                return False
        except:
            pass

    return True


def pkt_flag_processor(packet):
    if packet.getlayer(scp.TCP).flags == "SA":
        syn_detector_threader(packet)

    if packet.getlayer(scp.TCP).flags == "A":
        log_success_handshake(packet)


# for logging missing packet, and adding to number of missing packet
def log_missing_packet(packet_flag, src_ip, dst_ip):
    if verbose >= 3:
        logging(
            "No acknowledgement to "
            + packet_flag
            + " packet found after timeout between "
            + src_ip
            + " and "
            + dst_ip,
        )

    interaction_name = src_ip + " and " + dst_ip

    if interaction_name not in interaction_missing_packets:
        interaction_missing_packets[interaction_name] = 0

    interaction_missing_packets[interaction_name] += 1


# for logging a successful tcp handshake
def log_success_handshake(packet):
    if verbose >= 1:
        logging(
            "Successful TCP handshake between " + packet.src + " and " + packet.dst,
        )


def reset_interaction_missing_packets():
    global interaction_missing_packets
    interaction_missing_packets = {}


# SYN flood detector logger
def missing_packet_flood_detector(time_check, threshold):

    while True:
        time.sleep(time_check)

        if verbose >= 2:
            missing_packets = 0

            for interaction in interaction_missing_packets:
                missing_packets += interaction_missing_packets[interaction]

            logging(
                str(missing_packets)
                + " missing acknowledgement packets within the last "
                + str(time_check)
                + " seconds",
            )

        if verbose >= 0:
            for interaction in interaction_missing_packets:
                if interaction_missing_packets[interaction] >= threshold:
                    mac_ad = interaction.split(" and ")

                    logging(
                        "WARNING: SYN flood attack detected by "
                        + mac_ad[0]
                        + " targeting "
                        + mac_ad[1],
                    )

        reset_interaction_missing_packets()


synflood_detector_thread = threading.Thread(
    target=missing_packet_flood_detector, args=(syn_time_check, syn_threshold)
)


# PORTSCAN DETECTOR
# dictionary for holding unique devices and the ports they are accessing (used for port scan)
unique_interaction_accessing_port = {}


def reset_unique_port():
    global unique_interaction_accessing_port
    unique_interaction_accessing_port = {}


def port_scan_processor(packet):

    is_syn_flag = syn_filter(packet)

    if not is_syn_flag:
        return

    unique_port_organizer(
        packet, unique_interaction_accessing_port, [True, False]
    )  # only taking dport


def port_scan_detector():
    while True:
        time.sleep(ps_time_check)

        for interaction_name in unique_interaction_accessing_port:

            mac_ad = interaction_name.split(", ")
            if verbose >= 1:
                logging(
                    mac_ad[0]
                    + " accessed "
                    + str(len(unique_interaction_accessing_port[interaction_name]))
                    + " ports of "
                    + mac_ad[1]
                    + "'s connection",
                )

            if (
                len(unique_interaction_accessing_port[interaction_name][1])
                >= ps_threshold
            ):

                if verbose >= 0:
                    logging(
                        "WARNING: Portscan detected by "
                        + mac_ad[0]
                        + " targeting "
                        + mac_ad[1],
                    )

        reset_unique_port()


port_scan_detector_thread = threading.Thread(target=port_scan_detector)


# UDP flood detector
udpflood_record_reset_counter = 0
udp_pkts_info = {}


# function to send packet variable to other functions
def udp_flood_processor(packet):

    is_udp = udp_filter(packet)

    if not is_udp:
        return

    # creating a dictionary on udp_pkt_info to include unique ports
    unique_port_organizer(packet, udp_pkts_info, [True, True], [True, False])
    # [True, True] to record both source and destination ports
    # [True, False] to record the source IP address (written inside the key's name)


# listens for icmp packets, and cross checks them for correct source and destination for ip/mac address and ports with the udp packets info
def icmp_pkt_listener(packet):
    if not packet.haslayer(scp.ICMP):
        return

    # ICMP type 3 is Destination unreachable, ICMP code 3 is Port unreachable
    if (
        not packet.getlayer(scp.ICMP).type == 3
        and not packet.getlayer(scp.ICMP).code == 3
    ):
        return

    for interaction_name in udp_pkts_info:

        mac_ad = interaction_name.split(", ")

        dst_mac_ad = mac_ad[1]

        # extra separation and formatting because the interaction name includes IP for the source
        src_mac_and_ip = mac_ad[0].split("(")
        src_mac_ad = src_mac_and_ip[0]
        src_ip = ""

        # some UDP packets don't have IP layer, which means no IP source or destination
        if len(src_mac_and_ip) >= 2:
            src_ip = src_mac_and_ip[1].replace(")", "")

        # checking whether the UDP and ICMP response packet have the same source and destination IP/mac address
        if not packet.src == dst_mac_ad:
            continue

        if not packet.getlayer(scp.IP).dst == src_ip:
            continue

        # checking whether the UDP and ICMP response packet have the same source and destination ports
        for i, sport in enumerate(udp_pkts_info[interaction_name][0]):

            if not sport == packet.getlayer(scp.UDPerror).sport:
                continue

            if (
                udp_pkts_info[interaction_name][1][i]
                == packet.getlayer(scp.UDPerror).dport
            ):
                icmp_pkt_counter(src_mac_ad + ", " + dst_mac_ad)


interaction_icmp_pkt_count = {}


# to reset the recorded UDP packet information
def udpflood_record_reset():
    global udp_pkts_info
    udp_pkts_info = {}

    global interaction_icmp_pkt_count
    interaction_icmp_pkt_count = {}

    global udpflood_record_reset_counter
    udpflood_record_reset_counter = 0


def icmp_pkt_counter(interaction_name):

    if interaction_name not in interaction_icmp_pkt_count:
        interaction_icmp_pkt_count[interaction_name] = 0

    interaction_icmp_pkt_count[interaction_name] += 1


# detector for UDP flood
def udpflood_detector_threader(udpflood_record_reset_counter):
    while True:
        time.sleep(udp_time_check)

        run_reset_counter = True
        run_reset = False

        for interaction_name in interaction_icmp_pkt_count:
            mac_ad = interaction_name.split(", ")

            if verbose >= 1:

                logging(
                    str(interaction_icmp_pkt_count[interaction_name])
                    + " ICMP Destination unreachable (port unreachable) packets sent from "
                    + mac_ad[1]
                    + " to "
                    + mac_ad[0]
                )

            if interaction_icmp_pkt_count[interaction_name] >= udp_threshold:

                if verbose >= 0:
                    logging(
                        "WARNING: UDP flood detected by "
                        + mac_ad[0]
                        + " targeting "
                        + mac_ad[1]
                    )

                run_reset_counter = False
                run_reset = True

        if run_reset_counter:
            udpflood_record_reset_counter += 1

        max_counter = udp_info_time_reset / udp_time_check
        # makes it so udpflood records are reseted after udp_time_reset seconds (resets after a udp flood check)

        if udpflood_record_reset_counter >= max_counter or run_reset:
            udpflood_record_reset()


udpflood_detector_thread = threading.Thread(
    target=udpflood_detector_threader, args=(udpflood_record_reset_counter,)
)


# sending pckets to the correct detector
def processor(packet):
    # passing to syn flood detector
    syn_detector_threader(packet)
    # sorts and count unique ports (used for port scanning)
    port_scan_processor(packet)
    # passing to udp flood detector and icmp listener
    udp_flood_processor(packet)
    icmp_pkt_listener(packet)
    # passing to icmp type and code scanner


if __name__ == "__main__":
    synflood_detector_thread.start()
    port_scan_detector_thread.start()
    udpflood_detector_thread.start()
    scp.sniff(prn=processor)
