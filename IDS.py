import scapy.all as scp
from datetime import datetime
import threading
import time
import json


# Users can adjust these values
SYNFLOOD_THRESHOLD = 100  # minimum amount of missing packets in the period of syn_time_check to alert detection of SYN flood (Higher means less sensitive)

PORT_SCAN_THRESHOLD = 50  # minimum amount of unique accessed ports to alert port scan (higher means less sentitive)

udp_time_check = 5  # seconds for each UDP flood check (lower time means less sensitive)
UDPFLOOD_THRESHOLD = 100  # minimum amount of ICMP packets in response to UDP packets in the peroid of udp_time_check to alert UDP flood (higher means less sensitive)

DNS_AMP_THRESHOLD = 500  # minimum bytes a dns response packet size can be to trigger detector (higher means less sensitive)

verbose = 0  # log levels
# from 0 to 1
# -1 for no logs
# 0 for attack detection logs only (recommended)
# 1 for other networking logs (for monitoring)


# Users can adjust with caution (affects the effectiveness of the detection)
CHECK_RESETTABLE = 0.5  # seconds
reset_syn_memory_time = 30  # seconds, to reset the syn packet information in memory
reset_udp_flood_memory_time = (
    30  # seconds, to reset the collected udp packets information
)
reset_portscan_count_time = 30
ps_time_check = 2  # seconds to check the count of portscan port accessed
# FIXME: combine all time check time check


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


update_arp_table_thread = threading.Thread(target=update_arp_table)

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
reset_syn_memory = False
interaction_missing_packets = {}
interaction_syn_memory = {}


# main processor and function caller for synflood detector
def synflood_processor(packet):

    if tcp_flag_filter(packet, "S"):
        update_interaction_syn_memory(packet)

    if tcp_flag_filter(packet, "SA"):

        if check_ack_number(packet):
            update_interaction_syn_memory(packet)

    if tcp_flag_filter(packet, "A"):

        if check_ack_number(packet):
            log_success_handshake(packet)

    # checking and logging for synflood attack
    synflood_detected, synflood_src, synflood_dst = synflood_detector()
    if synflood_detected:
        log_synflood(synflood_src, synflood_dst)
        force_reset_syn_memory()

    # call the process to clear the interaction_syn_memory dictionary
    reset_syn_memory_process()


# update any incoming syn packet information to interaction_syn_memory dictionary
def update_interaction_syn_memory(packet):

    src_ip = packet.getlayer(scp.IP).src
    dst_ip = packet.getlayer(scp.IP).dst
    packet_seq = packet.getlayer(scp.TCP).seq
    src_mac_ad = packet.src
    dst_mac_ad = packet.dst

    interaction_name = src_mac_ad + ", " + dst_mac_ad

    if interaction_name not in interaction_syn_memory:
        interaction_syn_memory[interaction_name] = {
            "src_ip": [],
            "dst_ip": [],
            "seq_num": [],
        }

    interaction_syn_memory[interaction_name]["seq_num"].append(packet_seq)
    interaction_syn_memory[interaction_name]["src_ip"].append(src_ip)
    interaction_syn_memory[interaction_name]["dst_ip"].append(dst_ip)


# will reset interaction_syn_memory dictionary when reset_syn_memory is True
def reset_syn_memory_process():
    global reset_syn_memory

    if reset_syn_memory:
        interaction_syn_memory.clear()
        reset_syn_memory = False


# runs a countdown timer in a different thread to change reset_syn_memory to True
def reset_syn_memory_timer():
    try:
        while True:
            time.sleep(reset_syn_memory_time)
            force_reset_syn_memory()
    except KeyboardInterrupt as e:
        print(str(e) + ": Stopping reset_syn_memory_timer loop...")


reset_syn_memory_timer_thread = threading.Thread(target=reset_syn_memory_timer)


# changes reset_syn_memory to True
def force_reset_syn_memory():
    global reset_syn_memory
    reset_syn_memory = True


# checking if the packet's ack is found in the interaction_syn_memory dictionary
# returns True if matching packet is found
def check_ack_number(packet):
    is_valid_ack = False

    src_ip = packet.getlayer(scp.IP).src
    dst_ip = packet.getlayer(scp.IP).dst
    packet_ack = packet.getlayer(scp.TCP).ack
    src_mac_ad = packet.src
    dst_mac_ad = packet.dst

    # matching sequence and acknowledgement number is sequence_number + 1 = acknowledgement_number
    matching_seq = packet_ack - 1

    interaction_name = dst_mac_ad + ", " + src_mac_ad

    for syn_interaction_name in interaction_syn_memory:

        if not interaction_name == syn_interaction_name:
            continue

        for i, seq_num in enumerate(
            interaction_syn_memory[syn_interaction_name]["seq_num"]
        ):

            if not seq_num == matching_seq:
                continue

            if not interaction_syn_memory[syn_interaction_name]["src_ip"][i] == dst_ip:
                continue

            if not interaction_syn_memory[syn_interaction_name]["dst_ip"][i] == src_ip:
                continue

            # deletes the syn packet information if a matching ack packet is found
            del interaction_syn_memory[syn_interaction_name]["seq_num"][i]
            del interaction_syn_memory[syn_interaction_name]["src_ip"][i]
            del interaction_syn_memory[syn_interaction_name]["dst_ip"][i]

            is_valid_ack = True

            break

    return is_valid_ack


# detects if interactions have syn packets without acknowledgement that exceeds threshold
# returns True (if exceeds threshold), source_of_interaction, destination_of_interaction
def synflood_detector():
    synflood_detected = False, "", ""

    for interaction_name in interaction_syn_memory:
        if (
            len(interaction_syn_memory[interaction_name]["seq_num"])
            >= SYNFLOOD_THRESHOLD
        ):
            src_and_dst = interaction_name.split(", ")
            synflood_detected = True, src_and_dst[0], src_and_dst[1]

    return synflood_detected


# for logging a successful tcp handshake
def log_success_handshake(packet):
    if verbose >= 1:
        logging(
            "Successful TCP handshake between " + packet.src + " and " + packet.dst,
        )


# for logging a synflood
def log_synflood(src, dst):
    if verbose >= 0:
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


def port_scan_detector():
    try:

        global accessing_port_info_resetable

        while True:
            time.sleep(ps_time_check)

            accessing_port_info_resetable = False
            port_scan_detected = False

            for interaction_name in unique_interaction_accessing_port:

                mac_ad = interaction_name.split(", ")
                if verbose >= 1:
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

                    if verbose >= 0:
                        detect_attack_logs("Port scan", mac_ad[0], mac_ad[1])

                    port_scan_detected = True

            accessing_port_info_resetable = True

            if port_scan_detected:
                reset_accessing_port_info()

    except KeyboardInterrupt as e:
        print(str(e) + ": Stopping port_scan_detector loop...")


port_scan_detector_thread = threading.Thread(target=port_scan_detector)


def accessing_port_info_resetter():
    while True:
        time.sleep(reset_portscan_count_time)

        while True:

            if accessing_port_info_resetable:
                reset_accessing_port_info()
                break

            time.sleep(CHECK_RESETTABLE)


accessing_port_info_resetter_thread = threading.Thread(
    target=accessing_port_info_resetter
)

"""
UDP FLOOD DETECTOR
"""

udp_flood_memory_resettable = True

udp_pkts_info_memory = {}
interaction_icmp_pkt_count = {}


# function to send packet variable to other functions
def udp_flood_processor(packet):

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
def reset_udp_flood_memory():
    udp_pkts_info_memory.clear()
    interaction_icmp_pkt_count.clear()


# detector for UDP flood
def udpflood_detector():

    no_udpflood_detected_counter = 0
    # counts the number of times udpflood is not detected after every udp_time_check
    # if it exceeds a certain amount, it will reset the udp_pkts_info_memory and interaction_icmp_pkt_count
    try:
        global udp_flood_memory_resettable

        while True:
            time.sleep(udp_time_check)

            udp_flood_memory_resettable = False
            udp_flood_detected = False

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

                if interaction_icmp_pkt_count[interaction_name] >= UDPFLOOD_THRESHOLD:

                    if verbose >= 0:
                        detect_attack_logs("UDP flood", mac_ad[0], mac_ad[1])

                    # when a udp flood is detected, it will queue a udp_pkts_info_memory reset
                    udp_flood_detected = True

            udp_flood_memory_resettable = True

            if udp_flood_detected:
                reset_udp_flood_memory()
            # # runs if no udpflood is detected
            # no_udpflood_detected_counter += 1

            # # the max value for no_udpflood_detected_counter to initiate a force_reset_udp_pkts_info_memory
            # # calculation makes it so that force_reset_udp_pkts_info_memory happens every reset_udp_memory_time
            # max_counter = reset_udp_memory_time / udp_time_check

            # if (
            #     reset_udp_pkts_info_memory
            #     or no_udpflood_detected_counter >= max_counter
            # ):
            #     no_udpflood_detected_counter = 0
            #     reset_udp_flood_memory()

            # interaction_icmp_pkt_count.clear()
    except KeyboardInterrupt as e:
        print(str(e) + ": Stopping udpflood_detector loop...")


udpflood_detector_thread = threading.Thread(target=udpflood_detector)


def udp_flood_memory_resetter():
    while True:
        time.sleep(reset_udp_flood_memory_time)

        while True:

            if udp_flood_memory_resettable:
                reset_udp_flood_memory()
                break

            time.sleep(CHECK_RESETTABLE)


udp_flood_memory_resetter_thread = threading.Thread(target=udp_flood_memory_resetter)

"""
ARP SPOOFING DETECTOR
"""

arp_request_memory = {}


# main function for arp spoof detection
def arp_spoof_processor(packet):

    # filtering ARP packets
    if not packet.haslayer(scp.ARP):
        return

    arp_op = get_arp_operation(packet)

    # op = 1 is request packet
    if arp_op == 1:
        store_arp_request_thread = threading.Thread(
            target=store_arp_request, args=(packet,)
        )
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
                arp_spoof_logger(packet)
                mark_arp_spoof_thread = threading.Thread(
                    target=mark_arp_spoof, args=(5,)
                )
                mark_arp_spoof_thread.start()


def mark_arp_spoof(time_between):
    global num_arp_spoof_packet

    num_arp_spoof_packet += 1
    time.sleep(time_between)
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


# logs an arp spoof warning
def arp_spoof_logger(packet):
    attacker = packet.src
    target = packet.dst

    if verbose >= 0:
        detect_attack_logs("ARP spoofing", attacker, target)


"""
DNS Amplification detector
"""


# dns_query_record = {}
dns_amp_target_and_attacker = {}


def dns_amp_processor(packet):

    if not packet.haslayer(scp.UDP):
        return

    if packet.haslayer(scp.DNS):
        if packet.getlayer(scp.DNS).qr == 0:
            if check_spoof_dns_query(packet, global_arp_table):
                update_dns_amp_target_and_attacker(packet)

    # dns response packets
    if packet.getlayer(scp.UDP).sport == 53:
        if packet.len >= DNS_AMP_THRESHOLD:
            attacker = get_dns_amp_attacker(packet)
            dns_amp_logger(packet, attacker)


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


def dns_amp_logger(packet, attacker):
    if verbose >= 0:

        source = "UNKNOWN"

        if attacker:
            source = attacker

        detect_attack_logs("DNS amplification", source, packet.dst)


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
    udp_flood_processor(packet)
    # add arp spoofing detection
    arp_spoof_processor(packet)
    # passing to dns amplification detector
    dns_amp_processor(packet)


if __name__ == "__main__":
    configure_arp_table()
    update_arp_table_thread.start()
    reset_syn_memory_timer_thread.start()
    port_scan_detector_thread.start()
    accessing_port_info_resetter_thread.start()
    udpflood_detector_thread.start()
    udp_flood_memory_resetter_thread.start()
    scp.sniff(prn=processor)
