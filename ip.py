from scapy.all import *
import requests
from xml.dom import minidom
import xml
import pickle
import sqlite3
import sys, os
from ssdp_discovery import *
from dial import *

def menu_actions_service(service,c):
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

def menu_services_ip(ip,c):
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

## Affiche l'IP des hosts ayant répondu
def menu_ip(c):
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