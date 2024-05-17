import scapy.all as scp
import datetime as dt

count = 100
MAX_PKTFRAME_LENGTH = 1518


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

    return sorted_pkt


while True:
    # sniffing packets with time recorded
    time_before_sniff = dt.datetime.now()
    packets = scp.sniff(count=count)
    time_after_sniff = dt.datetime.now()

    filtered_pkt = large_pkt_filter(packets, MAX_PKTFRAME_LENGTH - 200)
    unique_pkt_loads = unique_load_pkt_sorter(filtered_pkt)
