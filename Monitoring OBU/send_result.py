#!/usr/bin/env python3
#-*-coding:utf-8-*-
import time, socket, sys
HOST = sys.argv[1]
print(HOST)
PORT = 1164
msg = "finished"
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
client_socket.sendall(msg.encode())
time.sleep(0.5)
client_socket.close()
