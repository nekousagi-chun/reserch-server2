from scapy.all import *

from datetime import datetime
import csv
import os
import shlex
import shutil
import subprocess
import sys

FILENAME = datetime.now().strftime("%Y%m%d%H%M")
FILENAME_WINDOW = datetime.now().strftime("window_%Y%m%d%H%M")
LOG_DIR = os.path.join(os.environ["HOME"], "count/result_window")
ALL_LOG_DIR = os.path.join(os.environ["HOME"], "count/result")
THRESHOLD = 3157
IFACE = "ens160"

ipdict = {}
ufw_rule = []

ip_param = ["version", "ihl", "tos", "len", "id", "flags",
            "frag", "ttl", "proto", "chksum", "src", "dst"]
tcp_param = ["sport", "dport", "seq", "ack", "dataofs",
             "reserved", "flags", "window", "chksum", "urgptr"]

def ip_count(src, window):
    # itemsになければ初期値0で追加
    if src not in ipdict:
        ipdict[src] = 0
    # ウィンドウサイズが閾値以下ならば+1
    if window < THRESHOLD:
        ipdict[src] = ipdict[src] + 1
        with open(os.path.join(LOG_DIR, FILENAME_WINDOW), 'a') as f:
            w = csv.writer(f, lineterminator='\n')
            w.writerow([src, window, ipdict[src]])
            print("FILENAME_WINDOWに書き込む")
        write_ufw(src)
    else:
    #ウィンドウサイズが閾値以上ならばvaluesを0で初期化
        ipdict[src] = 0


def write_ufw(src):
    # 辞書型に記録された情報itemsで，valuesが170回以上観測された場合はufwの設定をする
    if ipdict[src] >= 170 and src not in ufw_rule:
        cmd = "ufw insert 1 deny from {}".format(src)
        print(cmd)
        subprocess.run(shlex.split(cmd))
        print("------------------")
        print(src,ipdict[src])
        print("------------------")
        ufw_rule.append(src)


def packet_show(packet):
    # パケットの内容をcsv形式で記録していく
    ip_count(packet[IP].src, packet[TCP].window)
    try:
        with open(os.path.join(ALL_LOG_DIR, FILENAME), 'a') as f:
            w = csv.writer(f, lineterminator='\n')
            w.writerow([packet[IP].version, packet[IP].ihl, packet[IP].tos,
                        packet[IP].len, packet[IP].id, packet[IP].flags,
                        packet[IP].frag, packet[IP].ttl, packet[IP].proto,
                        packet[IP].chksum, packet[IP].src, packet[IP].dst,
                        packet[TCP].sport, packet[TCP].dport, packet[TCP].seq,
                        packet[TCP].ack, packet[TCP].dataofs,
                        packet[TCP].reserved, packet[TCP].flags,
                        packet[TCP].window, packet[TCP].chksum,
                        packet[TCP].urgptr])

    except IndexError:
        print("--TCP nothing---")


def main():
    header = ip_param + tcp_param

    with open(os.path.join(ALL_LOG_DIR, FILENAME), 'w') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(header)

    with open(os.path.join(LOG_DIR, FILENAME_WINDOW), 'w') as f:
        w = csv.writer(f, lineterminator='\n')
        w.writerow(["src", "window", "count"])

    sniff(filter="tcp and not src host 10.1.200.100",iface=IFACE, prn=packet_show)

    print(ipdict)


if __name__ == '__main__':
    main()
