#!/bin/sh

# Monitor Interface ON
ifconfig cw-mon-rxa up

# Channel Config
cd /opt/cohda/bin
./chconfig -s -w CCH -i wave-raw -c 172 -r a -e 0x88dc -a 3

# Monitoring Packets!!

let time_quantum=($1 + 15)

(sleep ${time_quantum} && kill -9 `pgrep -f llc`) &
(./llc rcap --HdrLen 52 --Interface cw-mon-rxa --OutputFilename llc_rcap_a.pcap --Meta)

sudo mv llc_rcap_a.pcap /home/user

# Parse Packets
cd /home/user
python parser.py $2



