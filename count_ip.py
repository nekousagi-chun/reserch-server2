from scapy.all import * 
import sys 
from datetime import datetime 
import subprocess
import shlex

filename =datetime.now().strftime("%Y%m%d%H%M") 
ipdict = {}

def ip_count(src,sport,ipdict):
    if src not in ipdict:
        ipdict[src] = [1,sport]
    else:
        ipdict[src][0] = ipdict[src][0] + 1

def write_ipfw(ipdict):
    for i in ipdict.keys():
        print("=================")
        print(i, ipdict[i])#ipアドレスと出現回数
        print("=================")
        if ipdict[i][0] == 10:
            """
            cmd_hping3 = "hping3 -I eth0 -c 1 -R -s 22222 -p {} {}".format(ipdict[i][1],i)
            subprocess.run(shlex.split(cmd_hping3))
            #cmd_rst = IP(dst=i)/TCP(dport=ipdict[i][1],flags="R")
            #send(cmd_rst)
            """
            cmd = "ufw insert 1 deny from {}".format(i)
            subprocess.run(shlex.split(cmd))
            """
            cmd_reload = "ufw reload"
            subprocess.run(shlex.split(cmd_reload))
            #cmd_close = IP(dst=i)/TCP(dport=80
            print("=================")
            print(i, ipdict[i])
            print("=================")
            """
            print("=================")
            
    print(ipdict)
        
def packet_show(packet):
    ip_count(packet[IP].src,packet[TCP].sport,ipdict)
    write_ipfw(ipdict)

    try:
        
        ip_param = ["version","ihl","tos","len","id","flags","frag","ttl","proto","chksum","src","dst"]
        
        tcp_param = ["sport","dport","seq","ack","dataofs","reserved","flags","window","chksum","urgptr","options"]
   
        with open(filename,'a') as file:
            file.write(str(packet[IP].version) + "," + \
                   str(packet[IP].ihl) + "," + \
                   str(packet[IP].tos) + "," + \
                   str(packet[IP].len) + "," + \
                   str(packet[IP].id) + "," + \
                   str(packet[IP].flags) + "," + \
                   str(packet[IP].frag) + "," + \
                   str(packet[IP].ttl) + "," + \
                   str(packet[IP].proto) + "," + \
                   str(packet[IP].chksum) + "," + \
                   str(packet[IP].src) + "," + \
                   str(packet[IP].dst) + "," + \
                   str(packet[TCP].sport) + "," + \
                   str(packet[TCP].dport) + "," + \
                   str(packet[TCP].seq) + "," + \
                   str(packet[TCP].ack) + "," + \
                   str(packet[TCP].dataofs) + "," + \
                   str(packet[TCP].reserved) + "," + \
                   str(packet[TCP].flags) + "," + \
                   str(packet[TCP].window) + "," + \
                   str(packet[TCP].chksum) + "," + \
                   str(packet[TCP].urgptr) + "\n")


    except IndexError:
        print("--TCP nothing---")


if __name__ == '__main__':
    with open(filename,'w') as file:
        print("version,ihl,tos,len,id,flags,frag,ttl,proto,chksum,src,dst,sport,dport,seq,ack,dataofs,reserved,flags,window,chksum,urgptr,options", file = file)

    sniff(filter="tcp and src host 10.1.200.10", count = 100, iface="ens160", prn=packet_show)
    #sniff(filter="tcp and src host 10.1.200.10", count = 100, iface="ens160", prn=packet_show)
    #sniff(filter="tcp and src host not 10.1.200.100", count = 100, iface="ens32", prn=packet_show)
