#!/usr/bin/env python3
#-*-coding:utf-8-*-

from socket import *
import subprocess

serverSock = socket(AF_INET, SOCK_STREAM)
serverSock.bind(('', 1164))
serverSock.listen(1)

connectionSock, addr = serverSock.accept()

print(str(addr), 'connection confirmed from this address.')

data1 = connectionSock.recv(1024)

serverSock.close()

subprocess.call(['./monitor.sh', data1, addr])


