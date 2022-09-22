from SCHCPParserTool.parser import SCHCParser
import binascii
import json

# Exaple with LoRaWAN -- IPv6/UDP 

# First we create an object called parser with the rules we will test (lorawan.json)

parser = SCHCParser()

# We add a DevEUI and AppSKey to the parser object:
DevEUI = '1122334455667788'
AppSKey = '00AABBCCDDEEFF00AABBCCDDEEFFAABB'

parser.changeDevEUI (DevEUI=DevEUI)
parser.changeAppSKey (AppSKey=AppSKey)

# Now, we will create a IPV6/UDP packet according to the lorawan.json RuleID

comp_ruleID = 101
dev_prefix = "fe80::" 
ipv6_app = "fe80::1"
udp_data = bytearray(52) # We create a 52 bytes of zeros

uncompressed = parser.generateIPv6UDP(comp_ruleID, dev_prefix, ipv6_app, udp_data = udp_data)
print(binascii.hexlify(uncompressed).decode('ascii'))

JSON_Hint = {"RuleIDValue": comp_ruleID, 
             "Direction": "DW"}

# Now we compress the packet:
json_comp, schc_pkt = SCHCParser.generate_schc_msg(parser, packet = uncompressed, hint=JSON_Hint)
print(len(schc_pkt))

json_comp = json.loads(json_comp)
padding = json_comp['Compression']['Padding']

print(binascii.hexlify(schc_pkt).decode('ascii'))
print(json_comp)

# Let's create fragments with AA
rule_id = 21 # AA Rule ID
JSON_Hint = {"RuleIDValue": rule_id, 
             "Direction": "DW",
             "MTU":30,
             }

# We generate the fragments to be sent, the parser is on json with all the values per fragment including RCS

json_frags, fragments = SCHCParser.generate_schc_msg(parser, packet = schc_pkt , hint = JSON_Hint, padding = padding)
print(json_frags)


ACK_OK_1 = binascii.unhexlify('1520')  # 00100000 ACK ok for first packet  15 in Fport
ACK_OK_2 = binascii.unhexlify('15c0')  # 11000000 ACK ok for second packet  


ack_ok_1_parsed = SCHCParser.parse_schc_msg(parser, schc_pkt=ACK_OK_1, dir= "UP")
print(ack_ok_1_parsed)

ack_ok_2_parsed = SCHCParser.parse_schc_msg(parser, schc_pkt=ACK_OK_2, dir= "UP")
print(ack_ok_2_parsed)





