from scapy.all import *

MDNS_IPv4 = "224.0.0.251"
MDNS_IPv6 = "ff02::fb"
MDNS_PORT = 5353
MDNS_TTL = 255
MDNS_QUERY = "_services._dns-sd._udp.local."
TIMEOUT = 2
##SERVICES = ["_pulse-server._tcp","_postgresql._tcp","_adisk._tcp",
##        "_webdav._tcp","_timbuktu._tcp","_acrobatSRV._tcp","_rfb._tcp",
##        "_workstation._tcp","_dpap._tcp","_mumble._tcp","_apt._tcp",
##        "_libvirt._tcp","_ssh._tcp","_svn._tcp","_telnet._tcp",
##        "_imap._tcp","_rtp._udp","_webdavs._tcp","_dacp._tcp",
##        "_airport._tcp","_printer._tcp","_sftp-ssh._tcp","_odisk._tcp",
##        "_udisks-ssh._tcp","_presence._tcp","_pop3._tcp","_iax._udp",
##        "_rss._tcp","_xpra._tcp","_adobe-vc._tcp","_shifter._tcp",
##        "_pdl-datastream._tcp","_home-sharing._tcp","_domain._udp",
##        "_smb._tcp","_vlc-http._tcp","_omni-bookmark._tcp","_daap._tcp",
##        "_ksysguard._tcp","_pgpkey-hkp._tcp","_distcc._tcp","_bzr._tcp",
##        "_touch-able._tcp","_ipps._tcp","_https._tcp","_http._tcp",
##        "_tp-https._tcp","_ntp._udp","_skype._tcp","_raop._tcp",
##        "_net-assistant._udp","_pulse-sink._tcp","_nfs._tcp",
##        "_h323._tcp","_presence_olpc._tcp","_tps._tcp","_realplayfavs._tcp",
##        "_rtsp._tcp","_pulse-source._tcp","_afpovertcp._tcp",
##        "_remote-jukebox._tcp","_ipp._tcp","_tftp._udp","_mpd._tcp",
##        "_lobby._tcp","_tp-http._tcp","_sip._udp","_ldap._tcp",
##        "_MacOSXDupSuppress._tcp","_tp._tcp","_ftp._tcp","_see._tcp"]


def getCommand(filename, numPKT):
        pcap_p = rdpcap(filename)
        print(pcap_p[numPKT].command())

def parseAnswer(answer, ipv):
        res = []
        #print(unans_v6.summary())
        for s, r in answer:
                #print(r.summary())
                #print(r.show())
                if ipv:
                        ip = r[IPv6].src
                        #print("IP :", r[IPv6].src)
                else:
                        ip = r[IP].src
                        #print("IP :", r[IP].src)
                        
                r[UDP].decode_payload_as(DNS)
                #print(r[DNS].show())
                count = r[DNS].ancount
                #print("Answer count : " + str(r[DNS].ancount))
                #answer = r[DNS].decode_payload_as(DNSRR)
                for i in range(count):
                        print("Services : " + str(r[DNS].an[i].rdata) + " / " + str(ip))
                        res.append(r[DNS].an[i].rdata)
                        #print(ipv6, " : ", r[DNS].summary(), "\n")
        return res


def resolve(domains):
        qd_list = []
        for i in range(len(domains)):
                qd_list.append(DNSQR(qtype="PTR", qname=str(domains[i], "utf-8")))
        
        mdns_query_v6 = IPv6(dst=MDNS_IPv6, hlim=MDNS_TTL)/ UDP(sport=MDNS_PORT, dport=MDNS_PORT) / DNS(qd=qd_list)
        mdns_query_v4 = IP(dst=MDNS_IPv4, ttl=MDNS_TTL)/ UDP(sport=MDNS_PORT, dport=MDNS_PORT) / DNS(qd=qd_list)

        #mdns_query_v6.show()
        #mdns_query_v4.show()

        print("----- Sending IPv4 MDNS resolve request -----")
        answer_v4, unans_v4 = sr(mdns_query_v4, timeout=TIMEOUT, multi=True)

        print("----- Sending IPv6 MDNS resolve request -----")
        answer_v6, unans_v6 = sr(mdns_query_v6, timeout=TIMEOUT, multi=True)

        print("\n###############################\n\n----- IPv4 MDNS responses -----")
        dn4 = parseAnswer(answer_v4, False)

        print("\n###############################\n\n----- IPv6 MDNS responses -----")
        dn6 = parseAnswer(answer_v6, True)

        dns = dn4 + dn6

        print(dns)



#getCommand("../MDNS.pcapng", 11)

mdns_query_v6 = IPv6(dst=MDNS_IPv6, hlim=MDNS_TTL)/ UDP(sport=MDNS_PORT, dport=MDNS_PORT) / DNS(qd=DNSQR(qtype="PTR", qname=MDNS_QUERY))
mdns_query_v4 = IP(dst=MDNS_IPv4, ttl=MDNS_TTL)/ UDP(sport=MDNS_PORT, dport=MDNS_PORT) / DNS(qd=DNSQR(qtype="PTR", qname=MDNS_QUERY))
print("----- Sending IPv4 MDNS discovery request -----")
answer_v4, unans_v4 = sr(mdns_query_v4, timeout=TIMEOUT, multi=True)

print("----- Sending IPv6 MDNS discovery request -----")
answer_v6, unans_v6 = sr(mdns_query_v6, timeout=TIMEOUT, multi=True)

print("\n###############################\n\n----- IPv4 MDNS responses -----")
dn4 = parseAnswer(answer_v4, False)

print("\n###############################\n\n----- IPv6 MDNS responses -----")
dn6 = parseAnswer(answer_v6, True)

dns = dn4 + dn6

resolve(dns)
