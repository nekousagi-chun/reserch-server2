from scapy.all import *
import sys
from datetime import datetime
import subprocess
import shlex
import os
import shutil

filename =datetime.now().strftime("%Y%m%d%H%M")
window_value =datetime.now().strftime("window_%Y%m%d%H%M")
ipdict = {}
ufw_rule = []

#ウィンドウサイズが400以下の情報を辞書型にして記録していく
def ip_count(src,window,ipdict):
    if src not in ipdict:
        ipdict[src] = 0

    if window < 3157:
        ipdict[src] = ipdict[src] + 1
        with open(os.path.join("/home/k598254/count/result_window",window_value),'a') as file:
            file.write(str(src) + "," + \
                       str(window) + "," + \
                       str(ipdict[src]) + "\n")
    else:
        ipdict[src] = 0


"""
    if window < 3157:
        print(src, window)
        if src not in ipdict:
            ipdict[src] = 1
        else:
            ipdict[src] = ipdict[src] + 1

        with open(os.path.join("/home/k598254/count/result_window",window_value),'a') as file:
            file.write(str(src) + "," + \
                       str(window) + "," + \
                       str(ipdict[src]) + "\n")
     else:
        ipdict[src] = 0
"""
#辞書型に記録された情報から，同じIPアドレスが10回観測された場合はufwの設定をする
def write_ipfw(ipdict):
    for i in ipdict.keys():
        if ipdict[i] >= 170 and not i in ufw_rule:
            cmd = "ufw insert 1 deny from {}".format(i)
            print(cmd)
            subprocess.run(shlex.split(cmd))
            print("------------------")
            print(i, ipdict[i])
            print("------------------")
            ufw_rule.append(i)

#パケットの内容をcsv形式で記録していく
def packet_show(packet):
    ip_count(packet[IP].src,packet[TCP].window,ipdict)
    write_ipfw(ipdict)

    try:

        ip_param = ["version","ihl","tos","len","id","flags","frag","ttl","proto","chksum","src","dst"]

        tcp_param = ["sport","dport","seq","ack","dataofs","reserved","flags","window","chksum","urgptr"]

        with open(os.path.join("/home/k598254/count/result",filename),'a') as file:
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
    with open(os.path.join("/home/k598254/count/result",filename),'w') as file:
        print("version,ihl,tos,len,id,flags,frag,ttl,proto,chksum,src,dst,sport,dport,seq,ack,dataofs,reserved,flags,window,chksum,urgptr", file = file)
    # with open(window_value,'w') as file:
    with open(os.path.join("/home/k598254/count/result_window",window_value),'w') as file:
        print("src,window,count", file = file)
    
    sniff(filter="tcp and not src host 10.1.200.100", iface="ens160", prn=packet_show)

    print(ipdict)
