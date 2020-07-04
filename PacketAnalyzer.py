#! /usr/bin/env python3
import sys
import logging
import socket

from scapy.all import *
from PortFilter import *
from SynFilter import *

file_handler = logging.FileHandler(filename='history.log')
stdout_handler = logging.StreamHandler(sys.stdout)
handlers = [file_handler]

logging.basicConfig(
    level=logging.DEBUG, 
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=handlers
)

ports_threshold = 3
syn_threshold = 15
synFilter = None
portls = []

verbose = False
no_dns = False
help = False
 
def check(pkt):
    src_ip = dst_port = ""
    if verbose:
        print(pkt.summary())
        logging.info("%s",pkt.summary())
    if IP in pkt:
        src_ip = str(pkt[IP].src)
    if TCP in pkt:
        dst_port = str(pkt[TCP].dport)
        if pkt[TCP].flags.S and pkt[TCP].flags.A:
            synFilter.incrementSynAck()
        elif pkt[TCP].flags.S and not pkt[TCP].flags.A:
            synFilter.incrementSyn()
        elif pkt[TCP].flags.A and not pkt[TCP].flags.S:
            synFilter.incrementAck()
        if synFilter.valuateSynFlood():
            syn_count = synFilter.getSynCount()
            print("[s] Threshold exceeded > Source IP: "+ src_ip+" - No. SYNs: "+str(syn_count))
            logging.warning("[s] Syn flood attempt, threshold exceeded > Source IP: %s, - No. SYNs: %d", src_ip, syn_count)
    elif UDP in pkt:
        if DNS in pkt and no_dns:
            return
        dst_port = str(pkt[UDP].dport)

    in_list = False    
    for i in portls:
        if i.getIP() == src_ip:
            i.checkPort(dst_port)
            if i.getPortListLenght() > ports_threshold:
                print("[p] Threshold exceeded > Source IP: " + src_ip + " - No. ports:" + str(i.getPortListLenght()))
                logging.warning("[p] Port mapping attempt, threshold exceeded > Source IP: %s - No. ports: %d", src_ip, i.getPortListLenght())
            in_list = True
            break
 
    if in_list == False:
        portls.append(PortFilter(src_ip, dst_port))
        if portls[-1].getPortListLenght() > ports_threshold:
            print("[a] Threshold exceeded > Source IP: " + src_ip + " - No. " + str(portls[-1].getPortListLenght()))
            logging.warning("[a] Port mapping attempt, threshold exceeded > Source IP: %s - No. %d", src_ip, portls[-1].getPortListLenght())
 
def select():
    hostname = socket.gethostname()
    print("[i] " + hostname +" available NICs:")
    ifs = get_if_list()
    logging.info("%s available NICs: %s", hostname, ifs)
    for i in range(0,len(ifs)):
        print("    " + str(i)+". "+ ifs[i])
    choosen = str (input("[i] Enter the name of the NIC to be analyzed: "))
    if choosen not in ifs:
        ex = Exception("[e] NIC "+choosen+" is not present or available.")
        logging.exception(ex, exc_info=False)
        logging.error("EXIT - {[***p4©K3t @ñ4l¥z3r***]} - version 1.0.0/author::cosmog97")
        raise ex
    return choosen

def help_info():
    logging.info("Displaying information and help")
    print ("Options: ")
    print ("  -h, -help    > Print the options and the legend of trace log.")
    print ("  -n, -nodns   > Connections with DNS servers are not detected.")
    print ("  -v, -verbose > The summary of each packet is printed to logger.")
    print ("Legend of trace log:")
    print ("[i] Info, [e] Exception, [a] New source IP analyzed (port scanning)")
    print ("[p] Port scanning attempt detected, [s] Syn flood attempt detected")
    logging.debug("EXIT - {[***p4©K3t @ñ4l¥z3r***]} - version 1.0.0/author::cosmog97")
    sys.exit(1)
 
if __name__ == "__main__":
    if ("-help" in sys.argv) or ("-h" in sys.argv):
        help = True
    if ("-nodns" in sys.argv) or ("-n" in sys.argv):
        no_dns = True
    if ("-verbose" in sys.argv) or ("-v" in sys.argv):
        verbose = True
    print ('{[***p4©K3t @ñ4l¥z3r***]} - version 1.0.0/author::cosmog97\nThe famous packet analyzer with intrusion detection capabilities!\n-----------------------------------------------------------------')
    logging.debug('START - {[***p4©K3t @ñ4l¥z3r***]} - version 1.0.0/author::cosmog97')
    if help:
        help_info()
    print("[i] Verbose mode: " + str(verbose) + ", NoDNSScan mode: " + str(no_dns))
    logging.info('Verbose mode: %s, NoDNSScan mode: %s', verbose, no_dns)
    print("[i] Ports threshold: " + str(ports_threshold) + ", Syn threshold: " + str(syn_threshold))
    logging.info('Ports threshold: %d, Syn threshold: %d', ports_threshold, syn_threshold)
    iface = select()
    synFilter = SynFilter(syn_threshold)
    print("[i] "+ iface +" selected. The capture starts now.\n-----------------------------------------------------------------")
    logging.info("%s selected. The capture starts now.", iface)
    sniff(iface=iface, prn=check, store=False)