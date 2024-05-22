import scapy.all as scp
from datetime import datetime
import threading
import time


# Users can adjust these values
time_check = (
    5  # seconds, time for each SYN flood check (lower time means less sensitive)
)
threshold = 100  # amount of failed packets in the period of time_check to alert detection of SYN flood (Higher means less sensitive)
verbose = 0
# 0 for SYN flood detection log only (no extra logging)
# 1 for sucessful TCP handshake log
# 2 for failed SYN/ACK and ACK packets


timeout = 2  # seconds, change only if you know what you are doing
failed_packets = 0


# temporary (until we integrate check_flag in sniff())
def check_flag(packet, flag):
    # try and except because some tcp packets dont have flags
    try:
        if packet.getlayer(scp.TCP).flags == flag:
            return packet
    except:
        pass

    return None


def start_flag_thread(packet, flag):

    # check for correct flag
    if not check_flag(packet, flag):
        return

    next_flag = None

    if flag == "S":
        next_flag = "SA"

    if flag == "SA":
        next_flag = "A"

    thread = threading.Thread(target=find_flag_thread, args=(packet, next_flag))
    thread.start()


def find_flag_thread(packet, flag):
    packet_src = packet.getlayer(scp.IP).src
    packet_dst = packet.getlayer(scp.IP).dst

    flag_name = None
    packets = None

    if flag == "SA":
        flag_name = "SYN/ACK"
        # sniff to find SYN/ACK
        packets = scp.sniff(
            filter="tcp and src host " + packet_dst + " and dst host " + packet_src,
            prn=lambda x: start_flag_thread(x, flag),
            timeout=timeout,
        )

    if flag == "A":
        flag_name = "ACK"
        # sniff to find ACK
        packets = scp.sniff(
            filter="tcp and src host " + packet_src + " and dst host " + packet_dst,
            prn=logging_ack_found,
            timeout=timeout,
        )

    # TEMPORARY: can remove after adding flag filters to sniff
    # checking to see if theres any flag packets after timeout
    flag_packet_found = False

    for packet in packets:
        if check_flag(packet, flag):
            flag_packet_found = True

    if flag_packet_found:
        return

    if verbose >= 1:
        print(datetime.now(), "No " + flag_name + " packet found after timeout")

    global failed_packets
    failed_packets += 1

    # TODO: detect for a SYN attack if flag_packet_found is false


# for logging a successful tcp handshake
def logging_ack_found(packet):
    if not check_flag(packet, "A"):
        return

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
        global failed_packets

        if failed_packets >= threshold:
            print(datetime.now(), "WARNING: SYN flood detected")
        failed_packets = 0
        time.sleep(time_check)


detector_thread = threading.Thread(
    target=check_failed_packets, args=(time_check, threshold)
)

detector_thread.start()


# checking for SYN packets
scp.sniff(prn=lambda x: start_flag_thread(x, "S"), filter="tcp")
