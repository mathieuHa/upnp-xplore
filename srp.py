# Script

# need winpcap
# sudo apt-get install python-scapy
from scapy.all import *
import requests
from xml.dom import minidom
import xml
import pickle
import sqlite3
import sys, os
from ssdp_discovery import *
print("Script start")

listen_time = 60
limit_packet = 0
folder_name = "files/"
debug = False
files = set()
list_device = list()
list_service = list()

conn = sqlite3.connect("srp.db")
c = conn.cursor()

def create_database(): 
	c.execute('''CREATE TABLE IF NOT EXISTS IP
				 (ip_id INTEGER PRIMARY KEY,
				 ip text UNIQUE)''')

	c.execute('''CREATE TABLE IF NOT EXISTS DEVICES
				 (device_id INTEGER PRIMARY KEY,
				 model_name text,
				 device_type text,
				 ip_id INTEGER, 
				 FOREIGN KEY (ip_id) REFERENCES IP (ip_id))''')

	c.execute('''CREATE TABLE IF NOT EXISTS SERVICES
				 (service_id INTEGER PRIMARY KEY ,
				 service_type text,
				 service_uid text,
				 scpd_url text,
				 ip_id INTEGER, 
				 FOREIGN KEY (ip_id) REFERENCES IP (ip_id))''')

	c.execute('''CREATE TABLE IF NOT EXISTS ACTIONS
				 (action_id INTEGER PRIMARY KEY ,
				 name text,
				 service_id INTEGER,
				 FOREIGN KEY (service_id) REFERENCES SERVICES (service_id))''')

	c.execute('''CREATE TABLE IF NOT EXISTS ARGS
				 (arg_id INTEGER PRIMARY KEY ,
				 name text,
				 type text,
				 action_id INTEGER,
				 FOREIGN KEY (action_id) REFERENCES ACTIONS (action_id))''')



def getStringFromNode(str, node):
	listNode = node.getElementsByTagName(str)
	newStr = "Empty"
	if len(listNode) > 0:
		newNode = listNode[0]
		if newNode.hasChildNodes():
			newStr = newNode.firstChild.data
		else:
			print("Error newNode hasChildNodes false")
	else:
		print("Error len(Listnode) <= 0")
	return newStr


def send_soap_request(ip_adresse, methode, service, list_arg):
	request = \
	"""<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding\" 
	<s:Body> 
		<u:%s xmlns:u=\"urn:schemas-upnp.org:service:%s\">\n""" % (methode, service)
	for arg in list_arg:
		request+="\t\t\t"+arg+"\n"
	request+=""" 
		<u/:> 
	</s:Body> 
</s:Envelope>"""
	print(request)

def get_value_arg(arg):
	s = input(" >> ")

	## sauvegarde des résultats
	for ind, resp in enumerate(response):
		print(resp.summary())
		print("")
		content = resp[Raw]
		content = str(content).split('\\r\\n')
		for x in content:
			if "LOCATION" in x.upper():
				print(x)
				listpos = [pos for pos, char in enumerate(x) if char == '/']
				if len(listpos) >= 3:
					end = listpos[len(listpos)-1]
					print(x[9:end])
					results.add((x[9:], x[9:end]))

	## sauvegarde la liste des services reçu précédement dans des fichiers
	for ind, url in enumerate(results):
		try:
			r = requests.get(url[0])
			f = open(folder_name + str(ind) + "_file.xml", "w")
			files.add((folder_name + str(ind) + "_file.xml", url[1]))
			f.write(r.text)
			f.close()
		except requests.exceptions.RequestException as e:
			print("Error getting the info : " + str(e))
			print("deleting the @ in the DB")
		# results.remove(url)

	return results
	#fichier = open(folder_name + "save.xml", 'wb')
	#pickler = pickle.Pickler(fichier)
	#pickler.dump(files)
	#fichier.close()


	#fichier = open(folder_name + "save.xml", 'rb')
	#depickler = pickle.Unpickler(fichier)
	#files = depickler.load()
	#fichier.close()



## On récupère maintenant les actions et arguments

	c.execute('''SELECT * FROM IP''')
	resp_ip = c.fetchall()

	files.clear()

## Enregistre les actions dans des fichier xml
	for ip in resp_ip:
		print(ip[0])
		print(ip[1])
		c.execute('''SELECT * FROM SERVICES WHERE ip_id = ?''', [ip[0]])
		resp_services = c.fetchall()
		for ind, service in enumerate(resp_services):
			print(service)
			try:
				print("SEARCHING : " + ip[1]+service[3])
				r = requests.get(ip[1] + service[3])
				f = open(folder_name + str(ind) + "_action.xml", "w")
				files.add((folder_name + str(ind) + "_action.xml", service[0]))
				f.write(r.text)
				f.close()
			except requests.exceptions.RequestException as e:
				print("Error getting the info : " + str(e))

	## Enregistre les actions et les arguments dans la bdd
	for ind, file in enumerate(files):
		print("\nOpening file " + str(ind) + " : " + file[0])
		try:
			xmldoc = minidom.parse(file[0])
			root = xmldoc.documentElement
			actions = root.getElementsByTagName('action')
			for action in actions:
				name = getStringFromNode('name', action)
				c.execute('''INSERT INTO ACTIONS (name, service_id)	VALUES (?, ?)''', (name, file[1]))
				action_id = c.lastrowid
				if action.hasChildNodes():
					arguments = action.getElementsByTagName('argument')
					for argument in arguments:
						name = getStringFromNode('name', argument)
						direction = getStringFromNode('direction', argument)
						c.execute('''INSERT INTO ARGS (name, type, action_id)	VALUES (?, ?, ?)''',
								  (name, direction, action_id))

		except xml.parsers.expat.ExpatError as e:
			print(str(e))

## Menu
def menu():
	print("---------------------------------------\n")
	print("1 : SEND SSDP DISCOVER")
	print("2 : LIST IP")
	print("3 : CLEAR DATABASE")
	print("h : HELP")
	print("q : EXIT")
	selection = input(" >> ")
	return selection


## Affiche l'IP des hosts ayant répondu
def menu_ip():
	s = ''
	while s != 'r' and s != 'q':
		c.execute('''SELECT * FROM IP''')
		list_ip = c.fetchall()

		print(str(len(list_ip)) + " HOST responded ")

		for ind, ip in enumerate(list_ip):
			print("IP HOST " + str(ip[0]) + " : " + ip[1])


		print()
		print("[number IP] : Explore")
		print("r : RETURN")
		print("q : EXIT")
		s = input(" >> ")
		for ind, ip in enumerate(list_ip):
			if s == str(ip[0]):
				menu_services_ip(ip)
	return s


def menu_services_ip(ip):
	s = ''
	while s != 'r' and s != 'q':
		print("Affichage des services pour l'HOST : " + ip[1])

		c.execute('''SELECT * FROM SERVICES WHERE ip_id = ?''', [ip[0]])
		resp_services = c.fetchall()

		for ind, service in enumerate(resp_services):
			print("[" + str(service[0]) + "] - " + service[2])

		print()
		print("[number Service] : Explore Service")
		print("r : RETURN")
		print("q : EXIT")

		s = input(" >> ")
		for ind, service in enumerate(resp_services):
			if s == str(service[0]):
				menu_actions_service(service)
	return s

def menu_actions_service(service):
	s = ''
	while s != 'r' and s != 'q':
		print("Affichage des actions pour le service : " + service[1])

		c.execute('''SELECT * FROM ACTIONS WHERE service_id = ?''', [service[0]])
		resp_actions = c.fetchall()

		for ind, action in enumerate(resp_actions):
			print("[" + str(action[0]) + "] - " + action[1])

		print()
		print("[number Action] : Explore Arguments")
		print("r : RETURN")
		print("q : EXIT")

		s = input(" >> ")
		for ind, action in enumerate(resp_actions):
			if s == str(action[0]):
				menu_arguments_action(action)
	return s

def menu_arguments_action(action):
	s = ''
	while s != 'r' or s != 'q':
		print("Affichage des arguments pour l'action : " + action[1])

		c.execute('''SELECT * FROM ARGS WHERE action_id = ?''', [action[0]])
		resp_args = c.fetchall()

		for ind, arg in enumerate(resp_args):
			print(" - " + arg[1] + " ["+arg[2]+"]")

		print()
		print("r : RETURN")
		print("q : EXIT")
		s = input(" >> ")
	return s



	

def clear_database():
	c.execute('''DELETE FROM IP ''')
	c.execute('''DELETE FROM SERVICES ''')
	c.execute('''DELETE FROM DEVICES ''')
	c.execute('''DELETE FROM ACTIONS ''')
	c.execute('''DELETE FROM ARGS ''')
	print("Clear Database Done")


def print_help():
	print("Affichage de l'aide")
	print("A L AIDE")

create_database()
print_help()

selection = ''
while selection != 'q':
	selection = menu()
	if selection == '1':
		send_discover_ssdp()
	if selection == '3':
		clear_database()
	if selection == '2':
		selection = menu_ip()
	if selection == 'h':
		print_help()
		send_soap_request("IP @", "SERVICE", "METHODE", ["arg1", "arg2"])
	if selection == 'q':
		print("GOODBYE")

conn.commit()

conn.close()

print("Script end")
