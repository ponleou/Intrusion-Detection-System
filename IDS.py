import scapy.all as scp
from datetime import datetime
import threading
import time
import json


# Users can adjust these values
syn_threshold = 100  # minimum amount of missing packets in the period of syn_time_check to alert detection of SYN flood (Higher means less sensitive)

ps_threshold = 40  # minimum amount of unique accessed ports to alert port scan (higher means less sentitive)

udp_time_check = 5  # seconds for each UDP flood check (lower time means less sensitive)
udp_threshold = 100  # minimum amount of ICMP packets in response to UDP packets in the peroid of udp_time_check to alert UDP flood (higher means less sensitive)

da_threshold = 500  # minimum bytes a dns response packet size can be to trigger detector (higher means less sensitive)

verbose = 0  # log levels
# from 0 to 1
# -1 for no logs
# 0 for attack detection logs only (recommended)
# 1 for other networking logs (for monitoring)


# Users can adjust with caution (affects the effectiveness of the detection)
reset_syn_memory_time = 30  # seconds, to reset the syn packet information in memory
max_arp_request_in_memory = 3  # max number of arp request packets stored in memory
reset_udp_memory_time = 30  # seconds, to reset the collected udp packets information
ps_time_check = 30  # seconds, change only if you know what you are doing

"""
GLOBAL FUNCTIONS
"""


def logging(msg, file_name="ids_logs.txt"):
    with open(file_name, "a") as f:
        f.write(str(datetime.now()) + ": " + msg + "\n")


def caught_error_logs(msg, file_name="ids_caught_errors.txt"):
    logging("ERROR: " + msg, file_name)


def detect_attack_logs(attack_type, attacker, target, file_name="ids_logs.txt"):
    logging(
        "WARNING: "
        + attack_type
        + " detected from "
        + attacker
        + " targeting "
        + target,
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
        if len(interaction_syn_memory[interaction_name]["seq_num"]) >= syn_threshold:
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
# dictionary for holding unique devices and the ports they are accessing (used for port scan)
unique_interaction_accessing_port = {}


def reset_unique_port():
    unique_interaction_accessing_port.clear()


def port_scan_processor(packet):
    if not tcp_flag_filter(packet, "S"):
        return

    unique_port_organizer(
        packet, unique_interaction_accessing_port, [True, False]
    )  # only taking src port


def port_scan_detector():
    try:
        while True:
            time.sleep(ps_time_check)

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
                    >= ps_threshold
                ):

                    if verbose >= 0:
                        detect_attack_logs("Port scan", mac_ad[0], mac_ad[1])

            reset_unique_port()
    except KeyboardInterrupt as e:
        print(str(e) + ": Stopping port_scan_detector loop...")


port_scan_detector_thread = threading.Thread(target=port_scan_detector)


"""
UDP FLOOD DETECTOR
"""
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
def force_reset_udp_pkts_info_memory():
    udp_pkts_info_memory.clear()
    interaction_icmp_pkt_count.clear()


# detector for UDP flood
def udpflood_detector():

    no_udpflood_detected_counter = 0
    # counts the number of times udpflood is not detected after every udp_time_check
    # if it exceeds a certain amount, it will reset the udp_pkts_info_memory and interaction_icmp_pkt_count
    try:
        while True:
            time.sleep(udp_time_check)

            reset_udp_pkts_info_memory = False

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
                        detect_attack_logs("UDP flood", mac_ad[0], mac_ad[1])

                    # when a udp flood is detected, it will queue a udp_pkts_info_memory reset
                    reset_udp_pkts_info_memory = True

            # runs if no udpflood is detected
            no_udpflood_detected_counter += 1

            # the max value for no_udpflood_detected_counter to initiate a force_reset_udp_pkts_info_memory
            # calculation makes it so that force_reset_udp_pkts_info_memory happens every reset_udp_memory_time
            max_counter = reset_udp_memory_time / udp_time_check

            if (
                reset_udp_pkts_info_memory
                or no_udpflood_detected_counter >= max_counter
            ):
                no_udpflood_detected_counter = 0
                force_reset_udp_pkts_info_memory()

            interaction_icmp_pkt_count.clear()
    except KeyboardInterrupt as e:
        print(str(e) + ": Stopping udpflood_detector loop...")


udpflood_detector_thread = threading.Thread(target=udpflood_detector)

"""
ARP SPOOFING DETECTOR
"""

arp_request_memory = {}
arp_table = {}
# TODO: take arp table from file
# TODO: configure own local arp table
# TODO: add self configured arp table to local use


# writing arp table into local file
def write_arp_table(file_name="arp_table.json"):
    with open(file_name, "w") as f:
        json.dump(arp_table, f)


# main function for arp spoof detection
def arp_spoof_processor(packet):

    # filtering ARP packets
    if not packet.haslayer(scp.ARP):
        return

    arp_op = get_arp_operation(packet)

    # op = 1 is request packet
    if arp_op == 1:
        store_arp_request(packet)

    # op =2 is reply packet
    if arp_op == 2:

        # checks whether a reply matches any request stored in memory
        # True if a reply matches a request, False if not
        is_valid_reply = arp_reply(packet)

        ip = packet.getlayer(scp.ARP).psrc
        mac_address = packet.getlayer(scp.ARP).hwsrc

        if is_valid_reply:

            # returns True if valid arp reply packet changes the arp table
            is_modified = update_arp_table(ip, mac_address)

            if is_modified:
                if verbose >= 1:
                    logging(
                        "ARP table has been modified, " + ip + " is at " + mac_address
                    )

        # process for invalid replies (reply without matching request)
        else:

            # checking whether invalid packet matches current arp table (ignores invalid reply if its the same)
            not_spoof_packet = check_arp_table(ip, mac_address)

            # if invalid reply doesn't match arp table, calls as arp spoof packet
            if not not_spoof_packet:
                arp_spoof_logger(packet)

    # clearing arp requests in memory when it reaches maximum memory
    arp_request_in_memory = 0
    arp_request_src_in_memory = 0

    for arp_request in arp_request_memory:
        arp_request_in_memory += len(
            arp_request_memory[arp_request][
                next(iter(arp_request_memory[arp_request].keys()))
            ]
        )

    arp_request_src_in_memory += len(arp_request_memory)

    if (
        arp_request_in_memory >= max_arp_request_in_memory
        or arp_request_src_in_memory >= max_arp_request_in_memory
    ):
        arp_request_memory.clear()


# stores arp requests packets to memory
def store_arp_request(packet):
    request_psrc = packet.getlayer(scp.ARP).psrc  # ip of source/requester
    request_hwsrc = packet.getlayer(scp.ARP).hwsrc  # mac address of source/requester

    request_pdst = packet.getlayer(scp.ARP).pdst  # ip of the requested

    if request_psrc not in arp_request_memory:
        arp_request_memory[request_psrc] = {"src_mac": [], "request_to": []}

    arp_request_memory[request_psrc]["request_to"].append(request_pdst)
    arp_request_memory[request_psrc]["src_mac"].append(request_hwsrc)


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


# updates arp table with ip and mac_address, returns True if there were any changes, False if the information remained the same
# TODO: remove if we have a self configured arp table
def update_arp_table(ip, mac_address):

    arp_table_is_modified = False

    if ip in arp_table:

        if arp_table[ip] == mac_address:
            return arp_table_is_modified

        arp_table_is_modified = True

    arp_table[ip] = mac_address

    # save arp table to local
    write_arp_table()

    return arp_table_is_modified


# checking whether an ip and mac address matches information inside arp table, returns False if it doesnt match
def check_arp_table(ip, mac_address):

    matches_arp_table = False
    # False means the ip and mac address doesnt match the arp table (its a spoofed packet)
    # True means the ip and mac address matches the arp table (its a safe invalid packet)

    for arp_ip in arp_table:

        if not ip == arp_ip:
            continue

        if arp_table[arp_ip] == mac_address:
            matches_arp_table = True

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
            if check_spoof_dns_query(packet, arp_table):
                update_dns_amp_target_and_attacker(packet)

    # dns response packets
    if packet.getlayer(scp.UDP).sport == 53:
        if packet.len >= da_threshold:
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
    reset_syn_memory_timer_thread.start()
    port_scan_detector_thread.start()
    udpflood_detector_thread.start()
    scp.sniff(prn=processor)
