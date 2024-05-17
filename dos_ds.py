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


# function to collect the unique loads of packet frames
def unique_load_collector(array):
    unique_loads = []

    for x in array:
        # checking for unique load of packet frames
        if x.load not in unique_loads:
            # appending the unique load value
            unique_loads.append(x.load)
    # for x in unique_load_pkts:
    #     unique_packet_load.append(x)
    # return unique_load_pkts


while True:
    # sniffing packets with time recorded
    time_before_sniff = dt.datetime.now()
    packets = scp.sniff(count=count)
    time_after_sniff = dt.datetime.now()

    filtered_pkt = large_pkt_filter(packets, MAX_PKTFRAME_LENGTH - 200)
    unique_pkt_loads = unique_load_collector(filtered_pkt)

    # for x in filtered_pkt:
    #     print(x.len)
    # return [pktframe_length for pktframe_length in pktframe_length_array if pktframe_length > min_length]

    # for j in range(count):
    #     packet_load_arr.append(packet[j])

    # unique(packet_load_arr)

    # print(len(unique_packet_load) + packet_no_load)
