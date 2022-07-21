from SCHCPParserTool.parser import SCHCParser
import binascii

parser = SCHCParser()
#parser.rule_file = "lorawan.json"
#parser.rm.Add(file=parser.rule_file)
#parser.rm.Print() # To Check the Rule

# We set a DevEUI and AppSKey in the parser object:
DevEUI = '1122334455667788'
AppSKey = '00AABBCCDDEEFF00AABBCCDDEEFFAABB'

parser.changeDevEUI (DevEUI=DevEUI)
parser.changeAppSKey (AppSKey=AppSKey)

ruleID = 22
udp_data = bytearray(200)

print (udp_data)
no_compress_pkt = parser.generateIPv6UDP(ruleID, udp_data = udp_data)

print(no_compress_pkt)
#no compress packets
schc_parsed_comp = parser.parse_schc_msg(schc_pkt=no_compress_pkt, ruleID=ruleID)
print(schc_parsed_comp)