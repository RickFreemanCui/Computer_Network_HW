from hexdump import hexdump
from scapy.all import Ether, IP

p = Ether()/IP()
s = bytes(p)
print(hexdump(s, result='return'))