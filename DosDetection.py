from scapy.all import *
from datetime import datetime


my_IP_Address = '10.0.0.35'

def action(dict_packets, dict_time, start_time, count, general_counter) :
    def detect(packet):
        global dict_packets
        global dict_time
        global start_time
        global count
        global general_counter
        flag = True

        if (TCP in packet) and (IP in packet):
            if (packet[TCP].flags & 2) :  #checks SYN flag
                #increase the number of packets received
                count = count+1
            #FOR IP ADDRESS ATTACK DETECTION:
                #get the source ip address
                source_ip = packet[IP].src
                
                if source_ip in dict_packets:
                    print(source_ip)
                    #if source ip address was encountered before, increment its value in dict_packets
                    dict_packets[source_ip] = dict_packets[source_ip] + 1
                    #if large number of packets is arriving within a short period of time from the same source ip address, detect DoS
                    if (dict_packets[source_ip] > 15) and (datetime.now() - dict_time[source_ip]).total_seconds() < 3:
                        print("Denial of Service is detected from :" + source_ip)
                        #removing The ATTACKER IP ADDR from the dictionaries
                        dict_packets.pop(source_ip)
                        dict_time.pop(source_ip)
                        Blocked_ip.append(source_ip)
                else:
                    for x in Blocked_ip :
                        if(source_ip == x):
                            flag = False
                            break
                    if(flag) :
                         print(source_ip)
                         # if source ip address is not encountered before, add it to dict_packets and set its value to 1
                         dict_packets[source_ip] = 1
                         # set first occurence of this ip
                         dict_time[source_ip] = datetime.now()
                         
        # if ip or mac address are spoofed and a very large traffic is detected, there might be a denial of service but not necessarly
        if (count>40) and (datetime.now() - start_time).total_seconds() < 1 :
            general_counter = general_counter +1
            start_time = datetime.now()
            count=0
        if general_counter >=5 :
            print("There might be a denial of service")
            general_counter =0
        # if statement for mac address
    return detect

#create a list containing the IPs that Perform DOS Attack
Blocked_ip = []
#create a dictionary that stores the number of packets coming from each ip address
dict_packets = {}

#create a dictionary that stores the time of arrival of first packet for each ip
dict_time = {}

start_time = datetime.now()

#counter for the number of packets
count =0
general_counter = 0


sniff(prn= action(dict_packets,dict_time, start_time, count, general_counter), iface=None, filter="")
