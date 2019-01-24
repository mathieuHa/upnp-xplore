from scapy.all import *
import requests
from xml.dom import minidom
import xml
import pickle
import sqlite3
import sys, os

def save_response(resp):

	response = resp
	## Affiche le résulats global des réponses
	print(str(len(response)) + " Paquets SSDP ADVERTISE reçu-s en " + str(listen_time) + " secondes")

	list_ip = set()
	for resp in response:
		list_ip.add(resp[IP].src)

	## Affiche l'IP des hosts ayant répondu
	print(str(len(list_ip)) + " HOST responded ")

	for ind, ip in enumerate(list_ip):
		print("IP HOST " + str(ind) + " : " + ip)

	results = set()

	## Création de la requête discover
def send_request():
	discover = "M-SEARCH * HTTP/1.1\r\n" \
			   "HOST: 239.255.255.250:1900\r\n" \
			   "MAN: \"ssdp:discover\" \r\n" \
			   "MX: 1\r\n" \
			   "USER-AGENT: Google Chrome/71.0.3578.98 Windows\r\n" \
			   "\r\n"

	## Broadcast de la requête discover sur le réseau local
	send(IP(dst="239.255.255.250") / UDP(sport=1900, dport=1900) / discover)

	## Ecoute du réseau pour les réponse à la requête discover
	response = sniff(filter="port 1900", count=limit_packet, lfilter=None, timeout=listen_time)

	return response

    ## Parcours tout les fichiers xml enregistrées et récupère les infos
## des services et device présents
def extract_resp(res):
	results = res
	for ind, file in enumerate(files):
		print("\nOpening file " + str(ind) + " : " + file[0])
		try:
			xmldoc = minidom.parse(file[0])
			root = xmldoc.documentElement
			devices = root.getElementsByTagName('device')
			services = root.getElementsByTagName('service')
			base_url = file[1]

			print("Présentation url  : " + base_url)

			if base_url != "Empty":
				print("\n----------------------------------")
				print("       Liste des devices :")
				print("----------------------------------")
				print()

				c.execute('''SELECT * FROM IP WHERE IP.ip = ? ''', [base_url])
				resp = c.fetchall()
				print("Resp IP  : " + str(resp))
				if len(resp) <= 0:
					c.execute('''INSERT INTO IP (ip) VALUES (?)''', [base_url])
					ip_id = c.lastrowid
				else:
					ip_id = str(resp[0][0])

				print("ipid " + str(ip_id))
				for device in devices:
					modelName = getStringFromNode('modelName', device)
					deviceType = getStringFromNode('deviceType', device)
					dev = {}
					dev["modelName"] = modelName
					dev["deviceType"] = deviceType
					list_device.append(dev)

					print("modelName    : " + modelName)
					print("deviceType   : " + deviceType)
					print()
					print("----------------------------------")
					print()
					c.execute(
						'''SELECT device_id FROM DEVICES WHERE DEVICES.ip_id = ? AND DEVICES.model_name = ? AND DEVICES.device_type = ? ''',
						(ip_id, modelName, deviceType))
					resp = c.fetchall()
					if len(resp) <= 0:
						c.execute('''INSERT INTO DEVICES (model_name, device_type, ip_id)
												VALUES (?, ?, ?)''', (modelName, deviceType, ip_id))
				print("\n----------------------------------")
				print("       Liste des services :")
				print("----------------------------------")
				print()

				for service in services:
					serviceType = getStringFromNode('serviceType', service)
					serviceId = getStringFromNode('serviceId', service)
					controlURL = getStringFromNode('controlURL', service)
					SCPDURL = getStringFromNode('SCPDURL', service)
					ser = {}
					ser["serviceType"] = serviceType
					ser["serviceId"] = serviceId
					ser["controlURL"] = controlURL
					ser["SCPDURL"] = SCPDURL
					list_service.append(ser)
					print("serviceType  : " + serviceType)
					print("serviceId    : " + serviceId)
					print("controlURL   : " + controlURL)
					print("SCPDURL      : " + SCPDURL)
					print()
					print("----------------------------------")
					print()
					c.execute(
						'''SELECT service_id FROM SERVICES WHERE SERVICES.ip_id = ? AND SERVICES.service_type = ? 
							AND SERVICES.service_uid = ? AND SERVICES.scpd_url = ? ''',
						(ip_id, serviceType, serviceId, SCPDURL))
					resp = c.fetchall()
					if len(resp) <= 0:
						c.execute('''INSERT INTO SERVICES (service_uid, service_type, scpd_url, ip_id)
																VALUES (?, ?, ?, ?)''',
								  (serviceId, serviceType, SCPDURL, ip_id))
		except xml.parsers.expat.ExpatError as e:
			print(str(e))

def send_discover_ssdp():
	print("Sending SSDP")
	resp = send_request()
	files = save_response(resp)
	extract_resp(files)


