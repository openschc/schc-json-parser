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

first_frag_ascci = "143e1660000000029211fffe80000000000000a06e66666470e5a1fe8000000000000000000000000000015c4030700292203000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

first_frag = binascii.unhexlify(first_frag_ascci)
print("frag:", first_frag)
schc_parsed_01 = SCHCParser.parse_schc_msg(parser, schc_pkt=first_frag)
print(schc_parsed_01)


#All_01 =  b'\x14(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
#All_0 =  b'\x14\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00'
#All_1 = b'\x14?\xa9\x8cX('

#compress_pkt = b'e\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
# We call the function to parse the fragments:

#Intermediate All_0
#schc_parsed_0 = SCHCParser.parse_schc_msg(parser, schc_pkt=All_0)
#print(schc_parsed_0)

#All_1
#schc_parsed_1 = SCHCParser.parse_schc_msg(parser, schc_pkt=All_1)
#print(schc_parsed_1)

#b'640c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
#b'65e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'

#Compress packets
#schc_parsed_comp = SCHCParser.parse_schc_msg(parser, schc_pkt=compress_pkt)
#print(schc_parsed_comp)

#compress_pkt_one_byte = b'e\xe0\x00\x00'
#schc_parsed_comp_byte = SCHCParser.parse_schc_msg(parser, schc_pkt=compress_pkt_one_byte)
#print(schc_parsed_comp_byte)