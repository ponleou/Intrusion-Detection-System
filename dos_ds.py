import scapy.all as scp
import datetime as dt

count = 100
MAX_PKTFRAME_LENGTH = 1518
threshold = 80  # percentage (lower means more sensitive)


# function to filter packet frames with large lengths
def large_pkt_filter(packets, min_length):
    filtered_pkt = []

    for i in range(0, count):
        try:
            if packets[i].len >= min_length:
                filtered_pkt.append(packets[i])
        except:
            # print(
            #     time_after_sniff,
            #     "Packet frame: ",
            #     packets[i].summary(),
            #     " no length found",
            # )
            continue

    return filtered_pkt


# filtering packets with loads
def pkt_with_load_filter(packets_array):
    filtered_pkt = []
    for pkt in packets_array:
        try:
            if pkt.load:
                filtered_pkt.append(pkt)
        except:
            continue
    return filtered_pkt


# function to collect the unique loads of packet frames
def unique_load_pkt_sorter(packets_array):
    # contains all the unique loads
    unique_loads = []

    sorted_pkts = []
    # array structure:
    # [
    #   [load_number,
    #       [packets_with_the_same_load...]
    #   ]...
    # ]
    # find the load of each sorted_pkts elements by unique_loads[load_number]

    # filtering the packets with load
    packets_with_load = pkt_with_load_filter(packets_array)
    total_pkts = len(packets_with_load)

    for x in packets_with_load:
        # checking for unique load of packet frames
        if x.load not in unique_loads:
            # appending the unique load value
            unique_loads.append(x.load)
    # sorting unique loads with unique numbers
    for load_number in range(len(unique_loads)):
        sorted_pkts.append([load_number, []])

    # sorting packets with the same load into one array
    for pkt in packets_with_load:
        for sorted_pkt in sorted_pkts:
            if pkt.load == unique_loads[sorted_pkt[0]]:
                sorted_pkt[1].append(pkt)

    return unique_loads, sorted_pkts, total_pkts


def heavy_packet_dos_detector(
    unique_pkt_loads, sorted_pkt_loads, total_pkts, threshold
):
    unique_load_test = len(unique_pkt_loads) <= total_pkts * (
        1 - (threshold / 100)
    )  # if unique loads is too little

    same_pkt_load_test = False  # if there is too many packets with the same load
    detected_pkt_load = []  # stores the load that is within multiple packets

    for sorted_pkt_load in sorted_pkt_loads:
        if len(sorted_pkt_load[1]) >= total_pkts * (threshold / 100):
            same_pkt_load_test = True
            detected_pkt_load.append(unique_pkt_loads[sorted_pkt_load[0]])

    if unique_load_test or same_pkt_load_test:
        print(
            dt.datetime.now(), "Potential DoS/DDoS Attack Detected: heavy packet flood"
        )


while True:
    # sniffing packets with time recorded
    time_before_sniff = dt.datetime.now()
    packets = scp.sniff(count=count)
    time_after_sniff = dt.datetime.now()

    # filter large packets
    filtered_pkt = large_pkt_filter(packets, MAX_PKTFRAME_LENGTH * (threshold / 100))

    # only scans when there are enough large packets in a loop
    if len(filtered_pkt) >= count * (threshold / 100):
        unique_pkt_loads, sorted_pkt_loads, total_pkts = unique_load_pkt_sorter(
            filtered_pkt
        )
        heavy_packet_dos_detector(
            unique_pkt_loads, sorted_pkt_loads, total_pkts, threshold
        )
