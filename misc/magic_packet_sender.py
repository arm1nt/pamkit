import dpkt
import socket

echo = dpkt.icmp.ICMP.Echo();

echo.id = 200;
echo.seq = 200;
echo.data = b'pamkit-start';

icmp = dpkt.icmp.ICMP();
icmp.type = dpkt.icmp.ICMP_ECHO
icmp.data = echo

print(icmp.pprint)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, dpkt.ip.IP_PROTO_ICMP);

s.sendto(icmp.pack(), ('ip_addr', 0))
