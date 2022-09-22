from SCHCPParserTool.parser import SCHCParser
import binascii

parser = SCHCParser()
#parser.rule_file = "lorawan.json"
#parser.rm.Add(file=parser.rule_file)
#parser.rm.Print() # To Check the Rule

# We add a DevEUI and AppSKey to the parser object:
DevEUI = '1122334455667788'
AppSKey = '00AABBCCDDEEFF00AABBCCDDEEFFAABB'

parser.changeDevEUI (DevEUI=DevEUI)
parser.changeAppSKey (AppSKey=AppSKey)

no_comp_rule = 22
udp_data = bytearray(36)

# Create a No compress packet to be fragmented later
no_compress_pkt = no_comp_rule.to_bytes(1,'big') + parser.generateIPv6UDP(no_comp_rule, udp_data = udp_data)
#print ("no_compress_pkt", no_compress_pkt, len(no_compress_pkt))

no_compress_pkt_parsed = SCHCParser.parse_schc_msg(parser, schc_pkt=no_compress_pkt)
#print(no_compress_pkt_parsed)

# Let's create fragments with AA
rule_id = 21 # AA Rule ID
JSON_Hint = {"RuleIDValue": rule_id, 
             "Direction": "DW",
             "MTU":30,
             }

# We generate the fragments to be sent, the parser is on json with all the values per fragment including RCS

json, fragments = SCHCParser.generate_schc_msg(parser, packet = no_compress_pkt ,hint = JSON_Hint)
#print(fragments)

ACK_OK00 = binascii.hexlify('20')  # 00100000 ACK ok for first packet  
ACK_OK01 = binascii.hexlify('a0')  # 10100000 ACK ok for second packet  
ACK_OK01 = binascii.hexlify('40')  # 01000000 ACK ok for last packet  

# Now we generate the ACK 
#.generate_schc_msg(parser, hint = JSON_Hint)
