import scapy.all as scp
from datetime import datetime
import threading
import time


# Users can adjust these values
time_check = (
    5  # seconds, time for each SYN flood check (lower time means less sensitive)
)
threshold = 100  # amount of missing packets in the period of time_check to alert detection of SYN flood (Higher means less sensitive)
verbose = 2
# 0 for SYN flood detection log only (no extra logging)
# 1 for sucessful TCP handshake log
# 2 for failed SYN/ACK and ACK packets


timeout = 2  # seconds, change only if you know what you are doing
missing_packets = 0


# temporary (until we integrate check_flag in sniff())
def check_flag(packet, flag):
    # try and except because some tcp packets dont have flags
    try:
        if packet.getlayer(scp.TCP).flags == flag:
            return packet
    except:
        pass

    return None


# function to run find_pkt_thread function in another thread
def start_find_pkt_thread(packet):
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
        timeout=timeout,
    )

    # TODO: function if the correct ack number is not found after timeout (missing packet)
    packet_missing = check_missing_packet(packets, seq_num)
    if packet_missing:
        log_missing_packet(packet_flag, src_ip, dst_ip)


#
def check_ack_number(packet, seq_number):

    correct_ack_number = seq_number + 1
    packet_ack_number = packet.getlayer(scp.TCP).ack

    if packet_ack_number == correct_ack_number:
        pkt_flag_processor(packet)


# TEMPORARY: can remove after adding flag filters to sniff
def check_missing_packet(sniffed_packets, seq_number):

    correct_ack_number = seq_number + 1

    # if there has been an ack packet for a syn packet, this loop will return false
    # if the packet is missing, it will return true
    for packet in sniffed_packets:

        packet_ack_number = packet.getlayer(scp.TCP).ack

        if packet_ack_number == correct_ack_number:
            return False

    return True
    # for packet in packets:
    #     if check_flag(packet, check_flag):
    #         flag_packet_found = True

    # if not flag_packet_found:
    #     if verbose >= 1:
    #         print(
    #             datetime.now(), "No " + flag_name_output + " packet found after timeout"
    #         )

    #     # if the packet with the flag is not found, one is added to the number of missing packets
    #     global missing_packets
    #     missing_packets += 1


def pkt_flag_processor(packet):
    if packet.getlayer(scp.TCP).flags == "SA":
        start_find_pkt_thread(packet)

    if packet.getlayer(scp.TCP).flags == "A":
        log_success_handshake(packet)


# for logging missing packet, and adding to number of missing packet
def log_missing_packet(packet_flag, src_ip, dst_ip):
    if verbose >= 1:
        print(
            datetime.now(),
            "No acknowledgement to"
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
    if verbose >= 2:
        print(
            datetime.now(),
            "Successful TCP handshake between "
            + packet.getlayer(scp.IP).src
            + " and "
            + packet.getlayer(scp.IP).dst,
        )


# SYN flood checker
def check_failed_packets(time_check, threshold):
    while True:
        global missing_packets

        if missing_packets >= threshold:
            print(datetime.now(), "WARNING: SYN flood detected")
        missing_packets = 0
        time.sleep(time_check)


detector_thread = threading.Thread(
    target=check_failed_packets, args=(time_check, threshold)
)

detector_thread.start()


# checking for SYN packets
scp.sniff(
    prn=lambda x: start_find_pkt_thread(x),
    filter="tcp",
)
