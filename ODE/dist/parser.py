import dpkt, matplotlib
matplotlib.use('Agg')
from matplotlib import pyplot as plt
import os, sys

temp = sys.argv[1]


f = open('llc_rcap_a.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)

target = 1          # send 10 packets per second identically
current_time = 0     
cnt = 0               # count variable range in 
y_values = []

# IEEE 802.11 source address 
# Original_src = [04:e5:48:00:10:00]
original_src = ['\x04', '\xe5', 'H', '\x00', '\x10', '\x00']

# Parse IUT's packets per second
try:
    for timestamp, buf in pcap:
        src = list(map(str, buf[106:112]))
        if src != original_src:
            cnt += 1
            if current_time == 0:
                current_time = timestamp
            elif timestamp - current_time > target:
                current_time = timestamp
                y_values.append(cnt)
                cnt = 0
        
    x_values = [i for i in range(0, len(y_values))]

    if len(y_values) == 0:
        max_height = 10
    else:
        max_height = max(y_values)
        
    plt.bar(x_values, y_values, width=0.6)
    plt.xlabel('Time(s)')
    plt.ylabel('Packets')
    plt.xlim(0,len(y_values))
    plt.ylim(0, max_height)
except:
    pass

# Draw Bar graph and save 'result.png' file

plt.savefig('result.png', dpi=200)

# Subprocess call(Send result.png) 
os.system("python3 send_result.py {0}".format(temp))

