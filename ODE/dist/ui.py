import sys
import paramiko
from scp import SCPClient
import socket
import time
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5 import uic

from PyQt5.QtWidgets import QApplication, QMainWindow
from datetime import datetime

form_class = uic.loadUiType("ODE_interface.ui")[0]
TEMP_LIST = []
PORT = 1164
N_R = []
IP_LIST = []
IP_LIST2 = []
MONITOR_IP = ""
flag = 0
account = ""
password = ""
sleeptime = 0
res = ""

with open('config.txt', 'r') as f:
	
	file_contents = f.readlines()
	IP_LIST = (file_contents[1].strip('\n')).split(' ')
	MONITOR_IP = file_contents[3].rstrip('\n')
	N_R.append(int(file_contents[5]))
	N_R.append(int(file_contents[7]))
	sleeptime = int(file_contents[5])/int(file_contents[7])
	account = file_contents[9]
	password = file_contents[11]

class Thread1(QThread):
	def __init__(self, parent):
		super().__init__(parent)
		
	def run(self):
		global res
		data1 = "none"
		serverSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		serverSock.bind(('', 1164))
		serverSock.listen(1)
		connectionSock, addr = serverSock.accept()
		data1 = connectionSock.recv(1024)
		res = data1.decode('utf-8')

		if res == "finished":
			global account
			global password
			global sleeptime
			filename = "result_" + str(datetime.now())[:-7].replace(' ', '_').replace(':', '_').replace('.', '_').replace('-', '_') + ".png"
			filepath = "../" + filename
			client = paramiko.SSHClient()
			client.load_system_host_keys()
			client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			#client.connect(MONITOR_IP.rstrip('\n'), username = account.rstrip('\n'), password = password.rstrip('\n'))
			client.connect(MONITOR_IP, username = account.rstrip('\n'), password = password)
			scp = SCPClient(client.get_transport())
			scp.get("/home/user/result.png", filepath)
			sys.exit()


	def stop(self):
		#Todo : QThread: Destroyed while thread is still running
		#Todo : make popup
		self.power = False
		self.quit()
		self.wait(3000)
    

class WindowClass(QMainWindow, form_class):
    	
	def __init__(self):
		super().__init__()
		self.setFixedSize(560, 600)
		self.setupUi(self)
		self.thread1 = Thread1(self)

		try:
			self.lineEdit_1.setText(IP_LIST[0])
			self.lineEdit_2.setText(IP_LIST[1])
			self.lineEdit_3.setText(IP_LIST[2])
			self.lineEdit_4.setText(IP_LIST[3])
		except:
			pass
		finally:
			self.lineEdit_5.setText(MONITOR_IP)
			self.lineEdit_6.setText(str(N_R[0]))
			self.lineEdit_7.setText(str(N_R[1]))

		self.AttackBtn.clicked.connect(self.AttackBtnClick)
		self.ExitBtn.clicked.connect(self.ExitBtnClick)
		self.lineEdit_1.editingFinished.connect(self.onChanged_1)
		self.lineEdit_2.editingFinished.connect(self.onChanged_2)
		self.lineEdit_3.editingFinished.connect(self.onChanged_3)
		self.lineEdit_4.editingFinished.connect(self.onChanged_4)
		self.lineEdit_5.editingFinished.connect(self.onChanged_5)
		self.lineEdit_6.editingFinished.connect(self.onChanged_6)
		self.lineEdit_7.editingFinished.connect(self.onChanged_7)
		

	def AttackBtnClick(self):
		
		global MONITOR_IP
		global IP_LIST2
		temp = MONITOR_IP
		if len(TEMP_LIST) != 1:
			IP_LIST.clear()
			TEMP_LIST.sort(key=lambda x : x[0])
			for e in TEMP_LIST:
				if e[1] != '':
					IP_LIST.append(e[1])
			
		if flag == 1:
			MONITOR_IP = IP_LIST[-1]
			del IP_LIST[-1]

		IP_LIST2 = list(set(IP_LIST))		
		global account
		global password
		print("\nSend attacking command to: ", end="")
		print(IP_LIST2)
		print("Number of attacking packet/rate: ", end="")
		print(N_R[0], N_R[1])
		print("Send monitoring command to: ", end="")
		print(temp)

		for i in range(len(IP_LIST2)):
			HOST = IP_LIST2[i].strip('\n')
			client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			client_socket.connect((HOST, PORT))
			client_socket.sendall(str(N_R[0]).encode())
			time.sleep(0.5)
			client_socket.sendall(str(N_R[1]).encode())
			client_socket.close()
	
		HOST = temp.strip('\n')
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect((HOST, PORT))

		msg = 'connect to monitoring PC'
		client_socket.sendall(msg.encode())
		time.sleep(0.5)
		client_socket.sendall(str(int(N_R[0])//int(N_R[1])).encode('utf-8'))
		client_socket.close()

		self.socketsocket()


	def ExitBtnClick(self):
		self.thread1.stop()
		sys.exit()


	def onChanged_1(self):
		text = self.lineEdit_1.text()
		TEMP_LIST.append((1,text))

	def onChanged_2(self):
		text = self.lineEdit_2.text()
		TEMP_LIST.append((2, text))

	def onChanged_3(self):
		text = self.lineEdit_3.text()
		TEMP_LIST.append((3,text))

	def onChanged_4(self):
		text = self.lineEdit_4.text()
		TEMP_LIST.append((4,text))
		
	def onChanged_5(self):
		text = self.lineEdit_5.text()
		TEMP_LIST.append((5,text))
		global flag
		flag = 1
	
	def onChanged_6(self):
		N_R.clear()
		text = self.lineEdit_6.text()
		N_R.append(text)

	def onChanged_7(self):
		text = self.lineEdit_7.text()
		N_R.append(text)

	def socketsocket(self):
		x = Thread1(self)
		x.start()

if __name__ == "__main__":
	app = QApplication(sys.argv)
	myWindow = WindowClass()
	myWindow.show()
	app.exec_()