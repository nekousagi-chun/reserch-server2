from scapy.all import *
import sys
from datetime import datetime
import subprocess
import shlex

filename =datetime.now().strftime("%Y%m%d%H%M")
ipdict = {}

def ip_count(src,window,ipdict):
    if window < 400:#もしwindowサイズが400以下ならばipdictに追加する
        if src not in ipdict:
            ipdict[src] = 1
        else:
            ipdict[src] = ipdict[src] + 1

def write_ipfw(ipdict):
    for i in ipdict.keys():#ipdictを読み込んで行く
        print("=================")
        print(i, ipdict[i])#ipアドレスと出現回数
        print("=================")
        if ipdict[i] == 10:
            cmd = "ufw insert 1 deny from {}".format(i)
            subprocess.run(shlex.split(cmd))
            print("~~~~~~~~~~~~~~~~~")
            print(i, ipdict[i])
            print("~~~~~~~~~~~~~~~~~")

    #print(ipdict)
def packet_show(packet):
    ip_count(packet[IP].src,packet[TCP].window,ipdict)
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
