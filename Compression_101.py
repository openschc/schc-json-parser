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

# Now, we will create a IPV6/UDP packet according to the lorawan.json RuleID

comp_ruleID = 101
dev_prefix = "fe80::" 
ipv6_app = "fe80::1"
udp_data = bytearray(10) # We create a 50 bytes of zeros

uncompressed = parser.generateIPv6UDP(comp_ruleID, dev_prefix, ipv6_app, udp_data = udp_data)
print(binascii.hexlify(uncompressed).decode('ascii'))

JSON_Hint = {"RuleIDValue": comp_ruleID, 
             "Direction": "DW"}

json, schc_pkt = SCHCParser.generate_schc_msg(parser, packet = uncompressed, hint=JSON_Hint)

# We can now print the schc packet in hexa:
print(binascii.hexlify(schc_pkt).decode('ascii'))

# Or we can also print the schc packet in JSON Format:
print(json)


# DUT Example

from_dut = binascii.unhexlify("6000000000091101fe800000000000000000000000000001fe80000000000000cf83a40938421ab820705c400009bfa100")
print("from dut", from_dut)
# Let's compress this packet using the rule 101

JSON_Hint = {"RuleIDValue": comp_ruleID, 
             "Direction": "DW"}

json, schc_pkt_dut = SCHCParser.generate_schc_msg(parser, packet = from_dut, hint=JSON_Hint)

# We can now print the schc packet in hexa:
print(binascii.hexlify(schc_pkt_dut).decode('ascii'))

# Or we can also print the schc packet in JSON Format:
print(json)

# We can parse the SCHC Packet
schc_parsed_comp = parser.parse_schc_msg(schc_pkt=schc_pkt_dut)

print(schc_parsed_comp)

