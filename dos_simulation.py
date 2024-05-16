import scapy.all as scp
from datetime import date

ip_layer = scp.IP(dst="192.168.8.101")
udp_layer = scp.UDP()
raw_layer = scp.Raw(65000)

package = ip_layer / udp_layer / raw_layer

scp.send(package, count=1000)
print(package)
