import scapy.all as scp
from datetime import datetime
import threading
import time


# Users can adjust these values
syn_time_check = 2  # seconds for each SYN flood check (lower time means less sensitive)
syn_threshold = 100  # minimum amount of missing packets in the period of time_check to alert detection of SYN flood (Higher means less sensitive)
ps_threshold = 40  # minimum amount of unique accessed ports to alert port scan (higher means less sentitive)
verbose = 1  # 0 to 3 (-1 for no logs)


ps_time_check = 30  # seconds, change only if you know what you are doing
syn_timeout = 2  # seconds, change only if you know what you are doing


# SYN FLOOD DETECTOR
interaction_missing_packets = {}


def logging(msg, file_name="ids_logs.txt"):
    with open(file_name, "w") as f:
        f.write(msg + "\n")


# function to run find_pkt_thread function in another thread
def syn_detector_threader(packet):

    try:
        if not packet.getlayer(scp.TCP).flags == "S":
            return
    except:
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
            str(datetime.now())
            + ": "
            + "No acknowledgement to "
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
    if verbose >= 2:
        logging(
            str(datetime.now())
            + ": "
            + "Successful TCP handshake between "
            + packet.src
            + " and "
            + packet.dst,
        )


def reset_interaction_missing_packets():
    global interaction_missing_packets
    interaction_missing_packets = {}


# SYN flood detector logger
def missing_packet_flood_detector(time_check, threshold):

    while True:
        time.sleep(time_check)

        if verbose >= 1:
            missing_packets = 0

            for interaction in interaction_missing_packets:
                missing_packets += interaction_missing_packets[interaction]

            logging(
                str(datetime.now())
                + ": "
                + str(missing_packets)
                + "missing acknowledgement packets within the last "
                + str(time_check)
                + " seconds",
            )

        if verbose >= 0:
            for interaction in interaction_missing_packets:
                if interaction_missing_packets[interaction] >= threshold:
                    ip = interaction.split(" and ")

                    logging(
                        str(datetime.now())
                        + ": "
                        + "WARNING: SYN flood attack detected by "
                        + ip[0]
                        + " targeting "
                        + ip[1],
                    )

        reset_interaction_missing_packets()


synflood_detector_thread = threading.Thread(
    target=missing_packet_flood_detector, args=(syn_time_check, syn_threshold)
)


# dictionary for holding unique devices and the ports they are accessing (used for port scan)
unique_interaction_accessing_port = {}


def reset_unique_port():
    global unique_interaction_accessing_port
    unique_interaction_accessing_port = {}


# PORTSCAN DETECTOR


def unique_port_organizer(packet):

    try:
        if not packet.getlayer(scp.TCP).flags == "S":
            return
    except:
        return

    interaction_name = packet.src + " and " + packet.dst

    if interaction_name not in unique_interaction_accessing_port:
        unique_interaction_accessing_port[interaction_name] = []

    if packet.dport not in unique_interaction_accessing_port[interaction_name]:
        unique_interaction_accessing_port[interaction_name].append(packet.dport)


def port_scan_detector():
    while True:
        time.sleep(ps_time_check)

        for interaction_name in unique_interaction_accessing_port:

            ip = interaction_name.split(" and ")
            if verbose >= 1:
                logging(
                    str(datetime.now())
                    + ": "
                    + ip[0]
                    + " accessed "
                    + str(len(unique_interaction_accessing_port[interaction_name]))
                    + " ports of "
                    + ip[1]
                    + "'s connection",
                )

            if len(unique_interaction_accessing_port[interaction_name]) >= ps_threshold:

                if verbose >= 0:
                    logging(
                        str(datetime.now())
                        + ": "
                        + "WARNING: Portscan detected by "
                        + ip[0]
                        + " targeting "
                        + ip[1],
                    )

        reset_unique_port()


port_scan_detector_thread = threading.Thread(target=port_scan_detector)


# sending pckets to the correct detector
def processor(packet):
    # passing to syn flood detector
    syn_detector_threader(packet)
    # sorts and count unique ports (used for port scanning)
    unique_port_organizer(packet)


synflood_detector_thread.start()
port_scan_detector_thread.start()
scp.sniff(prn=processor)
