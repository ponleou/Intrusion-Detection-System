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

"""
GLOBAL FUNCTIONS
"""


def logging(msg, file_name="ids_logs.txt"):
    with open(file_name, "a") as f:
        f.write(str(datetime.now()) + ": " + msg + "\n")


def caught_error_logs(msg, file_name="ids_caught_errors.txt"):
    logging("ERROR: " + msg, file_name)


def syn_filter(packet):
    is_syn_flag = False

    if not packet.haslayer(scp.TCP):
        return is_syn_flag

    try:
        packet_flag = packet.getlayer(scp.TCP).flags
        if packet_flag == "S":
            is_syn_flag = True
    except Exception as e:
        caught_error_logs("TCP packet without flags; " + str(e))

    return is_syn_flag


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

    # some UDP packets dont have IP layer
    try:
        if src_or_dst_ip[0]:
            packet_src += "(" + packet.getlayer(scp.IP).src + ")"

        if src_or_dst_ip[1]:
            packet_dst += "(" + packet.getlayer(scp.IP).dst + ")"
    except Exception as e:
        caught_error_logs("Transfer packet without IP layer; " + str(e))

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


"""
SYN FLOOD DETECTOR
"""
interaction_missing_packets = {}


# function to run find_pkt_thread function in another thread
def syn_detector_threader(packet):

    if not syn_filter(packet):
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

    packet_ack_number = get_ack_from_tcp(packet)

    if packet_ack_number == correct_ack_number:
        pkt_flag_processor(packet)


# TEMPORARY: can remove after adding flag filters to sniff
def check_missing_packet(sniffed_packets, seq_number):

    correct_ack_number = seq_number + 1

    # if there has been an ack packet for a syn packet, this loop will return false
    # if the packet is missing, it will return true
    for packet in sniffed_packets:

        packet_ack_number = get_ack_from_tcp(packet)

        if packet_ack_number == correct_ack_number:
            return False

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


"""
PORT SCAN DETECTOR
"""
# dictionary for holding unique devices and the ports they are accessing (used for port scan)
unique_interaction_accessing_port = {}


def reset_unique_port():
    global unique_interaction_accessing_port
    unique_interaction_accessing_port = {}


def port_scan_processor(packet):
    if not syn_filter(packet):
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


"""
UDP FLOOD DETECTOR
"""
udpflood_record_reset_counter = 0
udp_pkts_info = {}


# function to send packet variable to other functions
def udp_flood_processor(packet):

    if not packet.haslayer(scp.UDP):
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

            # some UDPerror packet doesnt have source port
            try:
                if not sport == packet.getlayer(scp.UDPerror).sport:
                    continue
            except Exception as e:
                caught_error_logs("UDPerror packet without ports; " + str(e))
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

"""
ARP SPOOFING DETECTOR
"""

arp_request_memory = {}
# TODO: clear memory after a timeout
arp_table = {}
# TODO: take arp table from file
# TODO: configure own local arp table


# writing arp table into local file
def write_arp_table(file_name="arp_table.txt"):
    with open(file_name, "w") as f:
        f.write(str(arp_table))


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

    print(
        arp_request_memory,
        "\n",
        reply_pdst,
        reply_psrc,
        reply_hwdst,
        "\n................",
    )

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

            if len(arp_request_memory[request_psrc]["request_to"]) == 0:
                del arp_request_memory[request_psrc]

            break

    return is_valid_reply


# updates arp table with ip and mac_address, returns True if there were any changes, False if the information remained the same
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
        logging(
            "WARNING: Spoofed ARP packet detected by "
            + attacker
            + " targeting "
            + target
        )


# TODO: test if database would update to the spoof arp if ran long enough


# sending pckets to the correct detector
def processor(packet):
    # passing to syn flood detector
    syn_detector_threader(packet)
    # sorts and count unique ports (used for port scanning)
    port_scan_processor(packet)
    # passing to udp flood detector and icmp listener
    udp_flood_processor(packet)
    icmp_pkt_listener(packet)
    # add arp spoofing detection
    arp_spoof_processor(packet)


if __name__ == "__main__":
    synflood_detector_thread.start()
    port_scan_detector_thread.start()
    udpflood_detector_thread.start()
    scp.sniff(prn=processor)
