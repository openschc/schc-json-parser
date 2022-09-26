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

first_frag = binascii.unhexlify("143e1660000000029211fffe80000000000000a06e66666470e5a1fe8000000000000000000000000000015c4030700292203000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
second_frag = binascii.unhexlify("14330000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
third_frag = binascii.unhexlify("14280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
forth_frag = binascii.unhexlify("141d0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
fifth_frag = binascii.unhexlify("14120000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
sixth_frag = binascii.unhexlify("14070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
seventh_frag_tiles = binascii.unhexlify("147b000000000000000000000000000000000000000000000000000000000000000000000000000000")
last_all1_only = binascii.unhexlify("147f4a2b0a9c")

schc_parsed_01 = SCHCParser.parse_schc_msg(parser, schc_pkt=first_frag)
print(schc_parsed_01)
schc_parsed_02 = SCHCParser.parse_schc_msg(parser, schc_pkt=second_frag)
#print(schc_parsed_02)
schc_parsed_03 = SCHCParser.parse_schc_msg(parser, schc_pkt=third_frag)
#print(schc_parsed_03)
schc_parsed_04 = SCHCParser.parse_schc_msg(parser, schc_pkt=forth_frag)
#print(schc_parsed_04)
schc_parsed_05 = SCHCParser.parse_schc_msg(parser, schc_pkt=fifth_frag)
#print(schc_parsed_05)
schc_parsed_06 = SCHCParser.parse_schc_msg(parser, schc_pkt=sixth_frag)
#print(schc_parsed_06)
schc_parsed_07 = SCHCParser.parse_schc_msg(parser, schc_pkt=seventh_frag_tiles)
#print(schc_parsed_07)
schc_parsed_all1_only = SCHCParser.parse_schc_msg(parser, schc_pkt=last_all1_only)
print(schc_parsed_all1_only)

ack = SCHCParser.reassembly(parser, fragment = schc_parsed_01, tiles_all1 = False)
ack = SCHCParser.reassembly(parser, fragment = schc_parsed_02, tiles_all1 = False)
ack = SCHCParser.reassembly(parser, fragment = schc_parsed_03, tiles_all1 = False)
ack = SCHCParser.reassembly(parser, fragment = schc_parsed_04, tiles_all1 = False)
ack = SCHCParser.reassembly(parser, fragment = schc_parsed_05, tiles_all1 = False)
ack = SCHCParser.reassembly(parser, fragment = schc_parsed_06, tiles_all1 = False)
ack = SCHCParser.reassembly(parser, fragment = schc_parsed_07, tiles_all1 = False)
print("here", ack)
#ack = SCHCParser.reassembly(parser, fragment = schc_parsed_all1_only, tiles_all1 = False)
print("here last", ack)

#fullpkt = binascii.unhexlify("1660000000029211fffe80000000000000a06e66666470e5a1fe8000000000000000000000000000015c403070029220300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
#print("deux", bitmap)

#print("lenn",len(full_pkt))

#full_pkt_pars = SCHCParser.parse_schc_msg(parser, schc_pkt=full_pkt)
#print(full_pkt_pars)