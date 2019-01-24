from scapy.all import *
import requests
from xml.dom import minidom
import xml
import pickle
import sqlite3
import sys, os
from ssdp_discovery import *
from ip import *



def send_discover_dial(limit_packet,listen_time):
    print("sending DIAL discovery")
    discover="M-SEARCH * HTTP/1.1\r\n"
    "HOST:239.255.255.250:1900\r\n"
    "ST:upnp:rootdevice\r\n"
    "MX:2\r\n"
    "MAN:\"ssdp:discover\"\r\n"
    resp = send_request(limit_packet,listen_time,discover)