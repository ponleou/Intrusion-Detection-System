import scapy.all as scp
from datetime import datetime
from threading import Thread
import time
import json

"""
GLOBAL VARIABLES
"""
# Users can adjust these values
SYNFLOOD_THRESHOLD = 100  # minimum number of missing packets in the period of MEMORY_RESET_TIME to alert detection of SYN flood (Higher means less sensitive)
UDPFLOOD_THRESHOLD = 100  # minimum number of ICMP packets in response to UDP packets in the peroid of MEMORY_RESET_TIME to alert UDP flood (higher means less sensitive)
PORT_SCAN_THRESHOLD = 50  # minimum number of unique accessed ports to alert port scan (higher means less sentitive)
DNS_AMP_THRESHOLD = 5
DNS_REPLY_BYTE_THRESHOLD = 500  # minimum bytes a dns response packet size can be to trigger detector (higher means less sensitive)

TIME_CHECK = 0.2  # seconds for detection check (lower time means less sensitive) for SYNFLOOD, UDPFLOOD and Port scan

VERBOSE = 0  # log levels
# from 0 to 1
# -1 for no logs
# 0 for attack detection logs only (recommended)
# 1 for other networking logs (for monitoring)


# Users can adjust with caution (affects the effectiveness and performance of the detection)
ARP_SPOOF_THRESHOLD = 1
MEMORY_RESET_TIME = 30  # seconds to reset the detection memory of packets
CHECK_RESETTABLE = 0.5  # seconds to check if a detection memory is able to reset


"""
ARP table configuration
"""

global_arp_table = {}

num_arp_spoof_packet = 0
# the number of arp spoof packet within the last set time


local_arp_table_file = "arp_table.json"


# function to configure a local arp table for the ids
def configure_arp_table():
    # creating the arp table dictionary
    arp_table = {}

    try:
        with open(local_arp_table_file, "r") as f:

            print("ARP table found, copying ARP table...")

            json_arp_table = json.load(f)
            arp_table = json_arp_table.copy()

    except:
        print("ARP table not found, creating ARP table...")

        generated_arp_table = collect_arp_table_info()
        arp_table = generated_arp_table.copy()

    write_arp_table(arp_table, local_arp_table_file)
    configure_global_arp_table(arp_table)
    print("ARP table configured.")


# copies the arp table to a global function for other functions in the ids to use
def configure_global_arp_table(arp_table):

    for arp_ip in arp_table:
        global_arp_table[arp_ip] = arp_table[arp_ip]


# sends arp request packets to all possible ips in the network to get mac addresses of devices in the network
# returns the arp table as a dictionary
def collect_arp_table_info():

    dictionary = {}

    PACKETS_SENT_PER_ROUND = 10
    MAX_VALUE_IPV4 = 254  # 255 is broadcast

    gateway_ip = scp.conf.route.route("0.0.0.0")[2]
    split_gateway_ip = gateway_ip.rsplit(".", 1)
    # right to left split, splits the first one (aka splits the last delimiter ".")
    # to get xxx.xxx.xxx and xxx
    packet_array = []

    for i in range(1, MAX_VALUE_IPV4 + 1):
        ip = split_gateway_ip[0] + "." + str(i)
        arp_request_broadcast = scp.Ether(dst="ff:ff:ff:ff:ff:ff") / scp.ARP(pdst=ip)
        packet_array.append(arp_request_broadcast)

        if (
            len(packet_array) >= PACKETS_SENT_PER_ROUND
            or MAX_VALUE_IPV4 - i < PACKETS_SENT_PER_ROUND
        ):
            answered_list = scp.srp(packet_array, timeout=0.5, verbose=False)[0]
            packet_array.clear()

            for answer in answered_list:
                ip = answer[1].getlayer(scp.ARP).psrc
                mac = answer[1].getlayer(scp.ARP).hwsrc
                dictionary[ip] = mac

    return dictionary


# writing arp table into local file
def write_arp_table(arp_table, file_name):
    with open(file_name, "w") as f:
        json.dump(arp_table, f)


# updates the arp table every 30 seconds (as set) by sending arp request packets to all possible ips in the network again
def update_arp_table():
    while True:
        time.sleep(30)

        updated_arp_table = collect_arp_table_info()

        while True:

            if num_arp_spoof_packet == 0:
                configure_global_arp_table(updated_arp_table)
                write_arp_table(global_arp_table, local_arp_table_file)
                break

            time.sleep(5)


update_arp_table_thread = Thread(target=update_arp_table)

"""
GLOBAL FUNCTIONS
"""


def logging(msg, file_name="ids_logs.txt"):
    with open(file_name, "a") as f:
        f.write(str(datetime.now()) + ": " + msg + "\n")


def caught_error_logs(msg, file_name="ids_caught_errors.txt"):
    logging("ERROR: " + msg, file_name)


def detect_attack_logs(attack_type, attacker_mac, target_mac, file_name="ids_logs.txt"):
    attack_ip = find_ip_from_mac(attacker_mac)
    target_ip = find_ip_from_mac(target_mac)

    logging(
        "WARNING: "
        + attack_type
        + " detected from "
        + attacker_mac
        + " ("
        + attack_ip
        + ")"
        + " targeting "
        + target_mac
        + " ("
        + target_ip
        + ")",
        file_name,
    )


def tcp_flag_filter(packet, flag):
    is_correct_flag = False

    if not packet.haslayer(scp.TCP):
        return is_correct_flag

    try:
        packet_flag = packet.getlayer(scp.TCP).flags
        if packet_flag == flag:
            is_correct_flag = True
    except Exception as e:
        caught_error_logs("TCP packet without flags; " + str(e))

    return is_correct_flag


def get_ack_from_tcp(packet):
    packet_ack_number = None

    if not packet.haslayer(scp.TCP):
        return packet_ack_number

    try:
        packet_ack_number = packet.getlayer(scp.TCP).ack
    except Exception as e:
        caught_error_logs("TCP packet without ack number; " + str(e))

    return packet_ack_number


def get_arp_operation(packet):
    arp_op = None

    if not packet.haslayer(scp.ARP):
        return arp_op

    try:
        arp_op = packet.getlayer(scp.ARP).op
    except Exception as e:
        caught_error_logs("ARP packet without operation value: " + str(e))

    return arp_op


def unique_port_organizer(
    packet, dictionary, src_or_dst_port=[True, True], src_or_dst_ip=[False, False]
):
    # src_or_dst_port can be changed to include or remove source port or destination port
    # src_or_dst_ip can be changed to include or remove source ip or destination ip (stays in the name of each array: interaction_name)
    packet_src = packet.src
    packet_dst = packet.dst

    # some packets dont have IP layer
    try:
        if src_or_dst_ip[0]:
            packet_src += "(" + packet.getlayer(scp.IP).src + ")"

        if src_or_dst_ip[1]:
            packet_dst += "(" + packet.getlayer(scp.IP).dst + ")"
    except Exception as e:
        caught_error_logs("Transfer packet without IP layer; " + str(e))

    interaction_name = packet_src + ", " + packet_dst

    if interaction_name not in dictionary:
        dictionary[interaction_name] = {"s_port": [], "d_port": []}

    if src_or_dst_port[0]:
        if packet.sport not in dictionary[interaction_name]["s_port"]:
            dictionary[interaction_name]["s_port"].append(packet.sport)

    if src_or_dst_port[1]:
        if packet.dport not in dictionary[interaction_name]["d_port"]:
            dictionary[interaction_name]["d_port"].append(packet.dport)


def find_ip_from_mac(mac_address):
    ip = "UNKNOWN"

    for arp_ip in global_arp_table:

        if mac_address == global_arp_table[arp_ip]:
            ip = arp_ip
            break

    return ip


"""
SYN FLOOD DETECTOR
"""

synflood_memory_resettable = True
interaction_synflood_memory = {}


# main processor and function to create the synflood memory
def synflood_processor(packet):

    if tcp_flag_filter(packet, "S"):
        update_interaction_synflood_memory(packet)

    if tcp_flag_filter(packet, "SA"):

        if check_ack_number(packet, True):

            update_interaction_synflood_memory(packet, True)

    if tcp_flag_filter(packet, "A"):

        if check_ack_number(packet):
            log_success_handshake(packet)


# update any incoming syn packet information to interaction_synflood_memory dictionary
def update_interaction_synflood_memory(packet, is_SA_flag=False):

    src_ip = packet.getlayer(scp.IP).src
    dst_ip = packet.getlayer(scp.IP).dst
    src_mac_ad = packet.src
    dst_mac_ad = packet.dst

    # if the tcp packet has SA flag, the dst and src will be flipped
    if is_SA_flag:
        src_ip = packet.getlayer(scp.IP).dst
        dst_ip = packet.getlayer(scp.IP).src
        src_mac_ad = packet.dst
        dst_mac_ad = packet.src

    packet_seq = packet.getlayer(scp.TCP).seq

    interaction_name = src_mac_ad + ", " + dst_mac_ad

    if interaction_name not in interaction_synflood_memory:
        interaction_synflood_memory[interaction_name] = {
            "src_ip": [],
            "dst_ip": [],
            "seq_num": [],
        }

    interaction_synflood_memory[interaction_name]["seq_num"].append(packet_seq)
    interaction_synflood_memory[interaction_name]["src_ip"].append(src_ip)
    interaction_synflood_memory[interaction_name]["dst_ip"].append(dst_ip)


# checking if the packet's ack is found in the interaction_synflood_memory dictionary
# returns True if matching packet is found
def check_ack_number(packet, is_SA_flag=False):
    is_valid_ack = False

    src_ip = packet.getlayer(scp.IP).src
    dst_ip = packet.getlayer(scp.IP).dst
    src_mac_ad = packet.src
    dst_mac_ad = packet.dst

    # if the tcp packet has SA flag, the dst and src will be flipped
    if is_SA_flag:
        src_ip = packet.getlayer(scp.IP).dst
        dst_ip = packet.getlayer(scp.IP).src
        src_mac_ad = packet.dst
        dst_mac_ad = packet.src

    packet_ack = packet.getlayer(scp.TCP).ack

    # matching sequence and acknowledgement number is sequence_number + 1 = acknowledgement_number
    matching_seq = packet_ack - 1

    interaction_name = src_mac_ad + ", " + dst_mac_ad

    for synflood_interaction_name in interaction_synflood_memory:

        if not interaction_name == synflood_interaction_name:
            continue

        for i, seq_num in enumerate(
            interaction_synflood_memory[synflood_interaction_name]["seq_num"]
        ):

            if not seq_num == matching_seq:
                continue

            if (
                not interaction_synflood_memory[synflood_interaction_name]["src_ip"][i]
                == src_ip
            ):
                continue

            if (
                not interaction_synflood_memory[synflood_interaction_name]["dst_ip"][i]
                == dst_ip
            ):
                continue

            # deletes the syn packet information if a matching ack packet is found
            del interaction_synflood_memory[synflood_interaction_name]["seq_num"][i]
            del interaction_synflood_memory[synflood_interaction_name]["src_ip"][i]
            del interaction_synflood_memory[synflood_interaction_name]["dst_ip"][i]

            is_valid_ack = True

            break

    return is_valid_ack


def reset_synflood_memory():
    interaction_synflood_memory.clear()


# detects if interactions have syn packets without acknowledgement that exceeds threshold
def synflood_detector():
    while True:
        time.sleep(TIME_CHECK)

        global synflood_memory_resettable
        synflood_memory_resettable = False

        synflood_detected = False

        for interaction_name in interaction_synflood_memory:
            src_and_dst = interaction_name.split(", ")
            synflood_src = src_and_dst[0]
            synflood_dst = src_and_dst[1]

            if (
                len(interaction_synflood_memory[interaction_name]["seq_num"])
                >= SYNFLOOD_THRESHOLD
            ):

                synflood_detected = True

                log_synflood(synflood_src, synflood_dst)

            if len(interaction_synflood_memory[interaction_name]["seq_num"]) > 0:
                if VERBOSE >= 1:
                    logging(
                        str(
                            len(
                                interaction_synflood_memory[interaction_name]["seq_num"]
                            )
                        )
                        + " SYN packets from "
                        + synflood_src
                        + " without ACK reply from "
                        + synflood_dst
                    )

        if synflood_detected:
            reset_synflood_memory()

        synflood_memory_resettable = True


synflood_detector_thread = Thread(target=synflood_detector)


# resets the synflood memory
def synflood_memory_resetter():
    while True:
        time.sleep(MEMORY_RESET_TIME)

        while True:

            if synflood_memory_resettable:
                reset_synflood_memory()
                break

            time.sleep(CHECK_RESETTABLE)


synflood_memory_resetter_thread = Thread(target=synflood_memory_resetter)


# for logging a successful tcp handshake
def log_success_handshake(packet):
    if VERBOSE >= 1:
        logging(
            "Successful TCP handshake between " + packet.src + " and " + packet.dst,
        )


# for logging a synflood
def log_synflood(src, dst):
    if VERBOSE >= 0:
        detect_attack_logs("SYN flood", src, dst)


"""
PORT SCAN DETECTOR
"""
accessing_port_info_resetable = True

# dictionary for holding unique devices and the ports they are accessing (used for port scan)
unique_interaction_accessing_port = {}


def reset_accessing_port_info():
    unique_interaction_accessing_port.clear()


def port_scan_processor(packet):
    if not tcp_flag_filter(packet, "S"):
        return

    unique_port_organizer(
        packet, unique_interaction_accessing_port, [True, False]
    )  # only taking src port


# detects for port scanning attack
def port_scan_detector():
    try:

        global accessing_port_info_resetable

        while True:
            time.sleep(TIME_CHECK)

            accessing_port_info_resetable = False
            port_scan_detected = False

            for interaction_name in unique_interaction_accessing_port:

                mac_ad = interaction_name.split(", ")
                if VERBOSE >= 1:
                    logging(
                        mac_ad[0]
                        + " accessed "
                        + str(
                            len(
                                unique_interaction_accessing_port[interaction_name][
                                    "s_port"
                                ]
                            )
                        )
                        + " ports of "
                        + mac_ad[1]
                        + "'s connection with TCP SYN packets",
                    )

                if (
                    len(unique_interaction_accessing_port[interaction_name]["s_port"])
                    >= PORT_SCAN_THRESHOLD
                ):

                    if VERBOSE >= 0:
                        detect_attack_logs("Port scan", mac_ad[0], mac_ad[1])

                    port_scan_detected = True

            accessing_port_info_resetable = True

            if port_scan_detected:
                reset_accessing_port_info()

    except KeyboardInterrupt as e:
        print(str(e) + ": Stopping port_scan_detector loop...")


port_scan_detector_thread = Thread(target=port_scan_detector)


# to reset t he port scanning information memory
def accessing_port_info_resetter():
    while True:
        time.sleep(MEMORY_RESET_TIME)

        while True:

            if accessing_port_info_resetable:
                reset_accessing_port_info()
                break

            time.sleep(CHECK_RESETTABLE)


accessing_port_info_resetter_thread = Thread(target=accessing_port_info_resetter)

"""
UDP FLOOD DETECTOR
"""

udpflood_memory_resettable = True

udp_pkts_info_memory = {}
interaction_icmp_pkt_count = {}


# function to send packet variable to other functions
def udpflood_processor(packet):

    if packet.haslayer(scp.UDP):
        # creating a dictionary on udp_pkt_info to include unique ports
        unique_port_organizer(packet, udp_pkts_info_memory, [True, True], [True, False])
        # [True, True] to record both source and destination ports
        # [True, False] to record the source IP address (written inside the key's name)

    if packet.haslayer(scp.ICMP):

        if packet.getlayer(scp.ICMP).type == 3 and packet.getlayer(scp.ICMP).code == 3:

            icmp_matches, interaction_name = check_icmp_with_udp_memory(packet)

            if icmp_matches:
                icmp_pkt_counter(interaction_name)


# cross checks icmp packets for correct source and destination for ip/mac address and ports with udp_pkts_info_memory
# returns True(if icmp matches with a udp packet from memory), interaction_name
def check_icmp_with_udp_memory(packet):

    icmp_matches = False, ""

    for interaction_name in udp_pkts_info_memory:

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

        # some icmp packets (icmpv6) dont have ip layer
        try:
            if not packet.getlayer(scp.IP).dst == src_ip:
                continue
        except Exception as e:
            caught_error_logs("ICMP packet without IP layer; " + str(e))

        # checking whether the UDP and ICMP response packet have the same source and destination ports
        for i, sport in enumerate(udp_pkts_info_memory[interaction_name]["s_port"]):

            # some UDPerror packet doesnt have ports
            try:
                if not sport == packet.getlayer(scp.UDPerror).sport:
                    continue
            except Exception as e:
                caught_error_logs("UDPerror packet without ports; " + str(e))
                continue

            if (
                udp_pkts_info_memory[interaction_name]["d_port"][i]
                == packet.getlayer(scp.UDPerror).dport
            ):
                interaction_name = src_mac_ad + ", " + dst_mac_ad
                icmp_matches = True, interaction_name
                break

    return icmp_matches


def icmp_pkt_counter(interaction_name):

    if interaction_name not in interaction_icmp_pkt_count:
        interaction_icmp_pkt_count[interaction_name] = 0

    interaction_icmp_pkt_count[interaction_name] += 1


# to reset the udp_pkts_info_memory and interaction_icmp_pkt_count
def reset_udpflood_memory():
    udp_pkts_info_memory.clear()
    interaction_icmp_pkt_count.clear()


# detector for UDP flood
def udpflood_detector():
    try:
        global udpflood_memory_resettable

        while True:
            time.sleep(TIME_CHECK)

            udpflood_memory_resettable = False
            udpflood_detected = False

            for interaction_name in interaction_icmp_pkt_count:
                mac_ad = interaction_name.split(", ")

                if VERBOSE >= 1:

                    logging(
                        str(interaction_icmp_pkt_count[interaction_name])
                        + " ICMP Destination unreachable (port unreachable) packets sent from "
                        + mac_ad[1]
                        + " to "
                        + mac_ad[0]
                    )

                if interaction_icmp_pkt_count[interaction_name] >= UDPFLOOD_THRESHOLD:

                    if VERBOSE >= 0:
                        detect_attack_logs("UDP flood", mac_ad[0], mac_ad[1])

                    # when a udp flood is detected, it will queue a udp_pkts_info_memory reset
                    udpflood_detected = True

            udpflood_memory_resettable = True

            if udpflood_detected:
                reset_udpflood_memory()

    except KeyboardInterrupt as e:
        print(str(e) + ": Stopping udpflood_detector loop...")


udpflood_detector_thread = Thread(target=udpflood_detector)


# to reset the udpflood memory
def udpflood_memory_resetter():
    while True:
        time.sleep(MEMORY_RESET_TIME)

        while True:

            if udpflood_memory_resettable:
                reset_udpflood_memory()
                break

            time.sleep(CHECK_RESETTABLE)


udpflood_memory_resetter_thread = Thread(target=udpflood_memory_resetter)

"""
ARP SPOOFING DETECTOR
"""

arp_request_memory = {}
arp_spoof_memory = {}
arp_spoof_memory_resettable = True


# main function for arp spoof detection
def arp_spoof_processor(packet):

    # filtering ARP packets
    if not packet.haslayer(scp.ARP):
        return

    arp_op = get_arp_operation(packet)

    # op = 1 is request packet
    if arp_op == 1:
        store_arp_request_thread = Thread(target=store_arp_request, args=(packet,))
        store_arp_request_thread.start()

    # op =2 is reply packet
    if arp_op == 2:

        # checks whether a reply matches any request stored in memory
        # True if a reply matches a request, False if not
        is_valid_reply = arp_reply(packet)

        # process for invalid replies (reply without matching request)
        if not is_valid_reply:

            ip = packet.getlayer(scp.ARP).psrc
            mac_address = packet.getlayer(scp.ARP).hwsrc

            # checking whether invalid packet matches current arp table (ignores invalid reply if its the same)
            not_spoof_packet = check_arp_table(ip, mac_address)

            # if invalid reply doesn't match arp table, calls as arp spoof packet
            if not not_spoof_packet:
                update_arp_spoof_memory(packet)

                mark_arp_spoof_thread = Thread(target=mark_arp_spoof)
                mark_arp_spoof_thread.start()


def update_arp_spoof_memory(packet):
    attacker = packet.src
    target = packet.dst

    interaction_name = attacker + ", " + target

    if interaction_name not in arp_spoof_memory:
        arp_spoof_memory[interaction_name] = 0

    arp_spoof_memory[interaction_name] += 1


# to prevent arp table from updating while there is a arp spoof happening in the past 5 seconds (to prevent local arp table polluting)
def mark_arp_spoof():
    global num_arp_spoof_packet

    num_arp_spoof_packet += 1
    time.sleep(5)
    num_arp_spoof_packet -= 1


# stores arp requests packets to memory for two second
def store_arp_request(packet):
    request_psrc = packet.getlayer(scp.ARP).psrc  # ip of source/requester
    request_hwsrc = packet.getlayer(scp.ARP).hwsrc  # mac address of source/requester

    request_pdst = packet.getlayer(scp.ARP).pdst  # ip of the requested

    if request_psrc not in arp_request_memory:
        arp_request_memory[request_psrc] = {"src_mac": [], "request_to": []}

    arp_request_memory[request_psrc]["request_to"].append(request_pdst)
    arp_request_memory[request_psrc]["src_mac"].append(request_hwsrc)

    time.sleep(2)

    for i, pdst in enumerate(arp_request_memory[request_psrc]["request_to"]):
        if request_pdst == pdst:
            del arp_request_memory[request_psrc]["request_to"][i]
            del arp_request_memory[request_psrc]["src_mac"][i]

    if (
        len(arp_request_memory[request_psrc]["request_to"]) == 0
        and arp_request_memory[request_psrc]["src_mac"] == 0
    ):
        del arp_request_memory[request_psrc]


# takes arp reply packet to cross-check request packet with memory, returns True if matching request packet is found/reply is valid
def arp_reply(packet):
    reply_psrc = packet.getlayer(scp.ARP).psrc

    reply_pdst = packet.getlayer(scp.ARP).pdst
    reply_hwdst = packet.getlayer(scp.ARP).hwdst

    is_valid_reply = False

    # cross-checking with request packet in memory
    for request_psrc in arp_request_memory:
        if not request_psrc == reply_pdst:
            continue

        for i, request_pdst in enumerate(
            arp_request_memory[request_psrc]["request_to"]
        ):
            if not request_pdst == reply_psrc:
                continue

            if not arp_request_memory[request_psrc]["src_mac"][i] == reply_hwdst:
                continue

            is_valid_reply = True

            del arp_request_memory[request_psrc]["request_to"][i]
            del arp_request_memory[request_psrc]["src_mac"][i]

            break

    return is_valid_reply


# checking whether an ip and mac address matches information inside arp table, returns False if it doesnt match
# only runs when invalid arp packets are found
def check_arp_table(ip, mac_address):
    matches_arp_table = False
    # False means the ip and mac address doesnt match the arp table (its a spoofed packet)
    # True means the ip and mac address matches the arp table (its a safe invalid packet)

    global num_arp_spoof_packet
    num_arp_spoof_packet += 1
    # adds a value to the arp spoof packet to stop global_arp_table from updating while function is running

    for arp_ip in global_arp_table:

        if not ip == arp_ip:
            continue

        if global_arp_table[arp_ip] == mac_address:
            matches_arp_table = True

    num_arp_spoof_packet -= 1

    return matches_arp_table


def reset_arp_spoof_memory():
    arp_spoof_memory.clear()


def arp_spoof_memory_resetter():
    while True:
        time.sleep(MEMORY_RESET_TIME)

        while True:

            if arp_spoof_memory_resettable:
                reset_arp_spoof_memory()
                break

            time.sleep(CHECK_RESETTABLE)


arp_spoof_memory_resetter_thread = Thread(target=arp_spoof_memory_resetter)


def arp_spoof_detector():
    while True:
        time.sleep(TIME_CHECK)

        global arp_spoof_memory_resettable
        arp_spoof_memory_resettable = False

        arp_spoof_detected = False

        for interaction_name in arp_spoof_memory:
            src_and_dst = interaction_name.split(", ")
            src_ip = src_and_dst[0]
            dst_ip = src_and_dst[1]

            if arp_spoof_memory[interaction_name] >= ARP_SPOOF_THRESHOLD:

                arp_spoof_detected = True

                arp_spoof_logger(src_ip, dst_ip)

            if arp_spoof_memory[interaction_name] > 0:
                logging(
                    str(arp_spoof_memory[interaction_name])
                    + " spoofed ARP packets sent from "
                    + src_ip
                    + " to "
                    + dst_ip
                )

        arp_spoof_memory_resettable = True

        if arp_spoof_detected:
            reset_arp_spoof_memory()


arp_spoof_detector_thread = Thread(target=arp_spoof_detector)


# logs an arp spoof warning
def arp_spoof_logger(attacker, target):
    if VERBOSE >= 0:
        detect_attack_logs("ARP spoofing", attacker, target)


"""
DNS Amplification detector
"""

dns_amp_memory_resettable = True
dns_amp_target_and_attacker = {}
interaction_dns_amp_memory = {}


def dns_amp_processor(packet):

    if not packet.haslayer(scp.UDP):
        return

    if packet.haslayer(scp.DNS):
        if packet.getlayer(scp.DNS).qr == 0:
            if check_spoof_dns_query(packet, global_arp_table):
                update_dns_amp_target_and_attacker(packet)

    # dns response packets
    if packet.getlayer(scp.UDP).sport == 53:
        if packet.len >= DNS_REPLY_BYTE_THRESHOLD:
            attacker_mac = "UNKNOWN"

            attacker = get_dns_amp_attacker(packet)

            if attacker:
                attacker_mac = attacker

            target_mac = packet.dst
            update_interaction_dns_amp_memory(target_mac, attacker_mac)


def update_interaction_dns_amp_memory(target_mac, attacker_mac):
    interaction_name = attacker_mac + ", " + target_mac

    if interaction_name not in interaction_dns_amp_memory:
        interaction_dns_amp_memory[interaction_name] = 0

    interaction_dns_amp_memory[interaction_name] += 1


def get_dns_amp_attacker(packet):
    attacker = None

    if not packet.haslayer(scp.IP):
        return attacker

    ip_src = packet.getlayer(scp.IP).src

    for ip in dns_amp_target_and_attacker:
        if ip == ip_src:
            attacker = dns_amp_target_and_attacker[ip]
            break

    return attacker


def update_dns_amp_target_and_attacker(packet):

    target_ip = packet.getlayer(scp.IP).src
    attacket_mac = packet.src

    if target_ip not in dns_amp_target_and_attacker:
        dns_amp_target_and_attacker[target_ip] = attacket_mac


def reset_dns_amp_memory():
    dns_amp_target_and_attacker.clear()
    interaction_dns_amp_memory.clear()


def dns_amp_detector():
    while True:
        time.sleep(TIME_CHECK)

        global dns_amp_memory_resettable
        dns_amp_memory_resettable = False

        dns_amp_detected = False

        for interaction_name in interaction_dns_amp_memory:

            attacker_and_target_mac = interaction_name.split(", ")
            src_mac = attacker_and_target_mac[0]
            dst_mac = attacker_and_target_mac[1]

            if interaction_dns_amp_memory[interaction_name] >= DNS_AMP_THRESHOLD:

                dns_amp_detected = True

                if VERBOSE >= 0:
                    detect_attack_logs("DNS amplification", src_mac, dst_mac)

            if VERBOSE >= 1:
                logging(
                    str(interaction_dns_amp_memory[interaction_name])
                    + " DNS reply packets detected that exceed minimum bytes threshold sent from "
                    + src_mac
                    + " to "
                    + dst_mac
                )

        dns_amp_memory_resettable = True

        if dns_amp_detected:
            reset_dns_amp_memory()


dns_amp_detector_thread = Thread(target=dns_amp_detector)


def dns_amp_memory_resetter():
    while True:
        time.sleep(MEMORY_RESET_TIME)

        while True:

            if dns_amp_memory_resettable:
                reset_dns_amp_memory()
                break

            time.sleep(CHECK_RESETTABLE)


dns_amp_memory_resetter_thread = Thread(target=dns_amp_memory_resetter)


def check_spoof_dns_query(packet, arp_table):
    is_spoof_dns_query = False

    if not packet.haslayer(scp.IP):
        return is_spoof_dns_query

    ipsrc = packet.getlayer(scp.IP).src
    macsrc = packet.src

    for ip in arp_table:
        if not ip == ipsrc:
            continue

        if arp_table[ip] == macsrc:
            break

        is_spoof_dns_query = True
        break

    return is_spoof_dns_query


# sending pckets to the correct detector
def processor(packet):
    # passing to syn flood detector
    synflood_processor(packet)
    # sorts and count unique ports (used for port scanning)
    port_scan_processor(packet)
    # passing to udp flood detector and icmp listener
    udpflood_processor(packet)
    # add arp spoofing detection
    arp_spoof_processor(packet)
    # passing to dns amplification detector
    dns_amp_processor(packet)


def detection_thread_starter():
    # synflood
    synflood_detector_thread.start()
    synflood_memory_resetter_thread.start()

    # port scan
    port_scan_detector_thread.start()
    accessing_port_info_resetter_thread.start()

    # udp flood
    udpflood_detector_thread.start()
    udpflood_memory_resetter_thread.start()

    # arp spoof
    arp_spoof_detector_thread.start()
    arp_spoof_memory_resetter_thread.start()

    # dns amplification
    dns_amp_detector_thread.start()
    dns_amp_memory_resetter_thread.start()


if __name__ == "__main__":
    # arp table
    configure_arp_table()
    update_arp_table_thread.start()

    detection_thread_starter()

    scp.sniff(prn=processor)
