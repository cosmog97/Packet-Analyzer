import sys
import logging
import random
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *
 

if __name__=="__main__":
    print("__________________________________")
    print("# cosmog97 | Port Scanner Attack #")
    print("##################################")
    ip_target = start_port = end_port = ""
    if len(sys.argv) > 1:
        ip_target = str(sys.argv[1])
        start_port = int(sys.argv[2])
        end_port = int(sys.argv[3])
        print("> Target IP: " + ip_target)
        print("> Start port: " +str(start_port))
        print("> End port: " +str(end_port))
    else:
        ip_target = str(input("> Insert target IP: "))
        start_port = int(input("> Insert start port: "))
        end_port = int(input("> Insert end port: "))

    if start_port == end_port:
        end_port+=1

    # Send SYN with random Src Port for each Dst port
    for dst_port in range(start_port, end_port):
        src_port = random.randint(1025,65534)
        resp = sr1(
            IP(dst=ip_target)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=1,
            verbose=0,
        )

        if resp is None:
            print(f"> Port {dst_port} is filtered (silently dropped).")

        elif(resp.haslayer(TCP)):
            if(resp.getlayer(TCP).flags == 0x12):
                # Send a gratuitous RST to close the connection
                send_rst = sr(
                    IP(dst=ip_target)/TCP(sport=src_port,dport=dst_port,flags='R'),
                    timeout=1,
                    verbose=0,
                )
                print(f"> Port {dst_port} is open.")

            elif (resp.getlayer(TCP).flags == 0x14):
                print(f"> Port {dst_port} is closed.")

        elif(resp.haslayer(ICMP)):
            if(
                int(resp.getlayer(ICMP).type) == 3 and
                int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]
            ):
                print(f"> Port {dst_port} is filtered (silently dropped).")