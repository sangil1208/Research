#!/bin/bash

cd /opt/cohda/bin
./chconfig -s -w CCH -i wave-raw -c 172 -r a -e 0x88dc -a 3

cd /home/user

echo -e "\nGenerating BSM packet ...\n"
./BSM_GENERATE

let a=($1/640+1)

touch bsm_cert.txt

for ((i=0; i<${a}; i++));
do
    cat bsm_basic.txt >> bsm_cert.txt
done

echo -e "\nBSM packet Generated!\n"

echo -e "\n\nSending $1 packets at Rate $2\n\n"
./test-tx -c 172 -i wave-raw -p 40 -a 3 -m MK2MCS_R34QAM64 -n $1 -r $2 -l 400 -e 0x88dc -g bsm

rm bsm_cert.txt

exit 0
