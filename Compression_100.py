from SCHCPParserTool.parser import SCHCParser
from scapy.all import *
import binascii

# Exaple with LoRaWAN -- IPv6/UDP 

# First we create an object called parser with the rules we will test (lorawan.json)

parser = SCHCParser()
parser.rule_file = "lorawan.json"
parser.rm.Add(file=parser.rule_file)
#parser.rm.Print() # To Check the Rule


# Now, we will create a IPV6/UDP packet according to the lorawan.json rule 100 [x64] using scapy

device_id = "lorawan:1122334455667788",
AppSKey = '00AABBCCDDEEFF00AABBCCDDEEFFAABB'
DevEUI = '1122334455667788'
IID  = SCHCParser.getdeviid(parser, AppSKey=AppSKey, DevEUI=DevEUI)

ipv6 = IPv6()
ipv6.src = "fe80::" + str(IID)[0:4] + ":" + str(IID)[4:8] + ":" + str(IID)[8:12] + ":" +str(IID)[12:16]
ipv6.dst = "fe80::1"
ipv6.tc = 0
ipv6.fl = 0
ipv6.nh = 17
ipv6.hl = 40

udp = UDP()
udp.sport = 23628
udp.dport = 4228

udp_data = bytes.fromhex('0'*50)
ipv6_udp = ipv6/udp/udp_data

uncompressed = bytes(ipv6_udp)

print(binascii.hexlify(uncompressed))
# Let's compress this packet using the rule 101 (this rule should be included inside the lorawan.json file) 

JSON_Hint = {"RuleIDValue": 100}

json, schc_pkt = SCHCParser.genrate_schc_msg(parser, packet = uncompressed, hint=JSON_Hint, device_id=device_id)

# We can now print the schc packet in hexa:
print(schc_pkt)

# Or we can also print the schc packet in JSON Format:
print(json)

