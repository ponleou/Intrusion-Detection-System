import scapy.all as scp

source_ip = input("Fake Source IP (blank for random IP): ")
target_ip = input("Target IP: ")
start_port = input("Start port: ")
end_port = input("End port: ")

MAX_PORT = 65535


def port_scan(source_ip, target_ip, start_port, end_port):
    packets = []
    for port in range(int(start_port), int(end_port) + 1):
        ip_layer = scp.IP(src=scp.RandIP(), dst=target_ip)

        if source_ip:
            ip_layer.src = source_ip

        packet = ip_layer / scp.TCP(dport=port, flags="S")
        packets.append(packet)
    scp.send(packets)


port_scan(source_ip, target_ip, start_port, end_port)
