from SCHCPParserTool.parser import SCHCParser
import binascii

# Exaple with LoRaWAN -- IPv6/UDP 

# First we create an object called parser with the rules we will test (lorawan.json)

parser = SCHCParser()
#parser.rule_file = "lorawan.json"
#parser.rm.Add(file=parser.rule_file)
#parser.rm.Print() # To Check the Rule

# We add a DevEUI and AppSKey to the parser object:
DevEUI = '1122334455667788'
AppSKey = '00AABBCCDDEEFF00AABBCCDDEEFFAABB'

parser.changeDevEUI (DevEUI=DevEUI)
parser.changeAppSKey (AppSKey=AppSKey)

# Now, we will create a IPV6/UDP packet according to the lorawan.json rule 100 [x64] using scapy

comp_ruleID = 101
dev_prefix = "fe80::" 
ipv6_dst = "fe80::1"
udp_data = bytes.fromhex('00'*50) # We create a 50 bytes of zeros

uncompressed = SCHCParser.generateIPv6UDP(parser, comp_ruleID, DevEUI, AppSKey, dev_prefix, ipv6_dst, udp_data)
print(binascii.hexlify(uncompressed).decode('ascii'))


# Let's compress this packet using the rule 101
JSON_Hint = {"RuleIDValue": comp_ruleID}
json, schc_pkt = SCHCParser.genrate_schc_msg(parser, packet = uncompressed, hint=JSON_Hint)

# We can now print the schc packet in hexa:
print(schc_pkt)

# Or we can also print the schc packet in JSON Format:
print(json)

