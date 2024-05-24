import scapy.all as scp
from datetime import datetime
import threading
import time


# Users can adjust these values
syn_time_check = (
    2  # seconds, time for each SYN flood check (lower time means less sensitive)
)
syn_threshold = 100  # amount of missing packets in the period of time_check to alert detection of SYN flood (Higher means less sensitive)
syn_verbose = -1
# 0 for SYN flood detection log only (no extra logging)
# 1 for number of missing packets log
# 2 for failed SYN/ACK and ACK packets
# 3 for sucessful TCP handshake log


syn_timeout = 2  # seconds, change only if you know what you are doing
missing_packets = 0


# SYN FLOOD DETECTOR
# function to run find_pkt_thread function in another thread
def syn_detector_threader(packet):
    # dst_ip is put for src_ip, and src_ip is put for dst_ip
    dst_ip = packet.getlayer(scp.IP).src
    src_ip = packet.getlayer(scp.IP).dst
    packet_seq = packet.getlayer(scp.TCP).seq
    packet_flag = str(packet.getlayer(scp.TCP).flags)

    thread = threading.Thread(
        target=find_ack_pkt_thread,
        args=(packet_seq, src_ip, dst_ip, packet_flag),
    )
    thread.start()


# function to find the correct acknowledgement number packet, will be ran in a seperate thread
def find_ack_pkt_thread(seq_num, src_ip, dst_ip, packet_flag):

    packets = scp.sniff(
        filter="tcp and src host " + src_ip + " and dst host " + dst_ip,
        prn=lambda x: check_ack_number(x, seq_num),
        timeout=syn_timeout,
    )

    # double checking and handling missing acknowledgement packet
    packet_missing = check_missing_packet(packets, seq_num)
    if packet_missing:
        log_missing_packet(packet_flag, src_ip, dst_ip)


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
    if syn_verbose >= 2:
        print(
            datetime.now(),
            "No acknowledgement to "
            + packet_flag
            + " packet found after timeout between "
            + src_ip
            + " and "
            + dst_ip,
        )

    global missing_packets
    missing_packets += 1


# for logging a successful tcp handshake
def log_success_handshake(packet):
    if syn_verbose >= 3:
        print(
            datetime.now(),
            "Successful TCP handshake between "
            + packet.getlayer(scp.IP).src
            + " and "
            + packet.getlayer(scp.IP).dst,
        )


# SYN flood detector logger
def missing_packet_flood_detector(time_check, threshold):
    while True:
        time.sleep(time_check)
        global missing_packets

        if syn_verbose >= 1:
            print(
                datetime.now(),
                missing_packets,
                "missing acknowledgement packets within the last "
                + str(time_check)
                + " seconds",
            )
        if syn_verbose >= 0:
            if missing_packets >= threshold:
                print(
                    datetime.now(),
                    "WARNING: SYN flood attack detected within the last "
                    + str(time_check)
                    + " seconds (missing packets exceed threshold)",
                )
        missing_packets = 0


synflood_detector_thread = threading.Thread(
    target=missing_packet_flood_detector, args=(syn_time_check, syn_threshold)
)

synflood_detector_thread.start()


# PORTSCAN DETECTOR
ps_timeout = 2
ps_threshold = 100

# dictionary for holding unique dport and amount
unique_port = {}


def port_scan_starter(packet):

    try:
        packet.dport
    except:
        return

    print(packet.dport)
    if packet.dport not in unique_port:
        unique_port[packet.dport] = 1
        return

    unique_port[packet.dport] += 1


def port_scan_detector():
    while True:
        time.sleep(ps_timeout)
        print(unique_port)
        if len(unique_port) >= ps_threshold:
            print(datetime.now(), "WARNING: Portscan detected")


port_scan_detector()


# sending pckets to the correct detector
def processor(packet):

    # passing to syn flood detector
    try:
        if packet.getlayer(scp.TCP).flags == "S":
            syn_detector_threader(packet)
    except:
        pass

    print("test")
    # passing to port scan detector
    port_scan_starter(packet)


scp.sniff(prn=lambda x: processor(x))
