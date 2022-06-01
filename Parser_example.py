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

All_01 =  b'\x14(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
All_0 =  b'\x14\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00'
All_1 = b'\x14?\xa9\x8cX('

compress_pkt = b'e\xe0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


device_id = "lorawan:1122334455667788" #This should be the same as in the lorawan.json file

# We call the function to parse the fragments:

#First All_0
schc_parsed_01 = SCHCParser.parse_schc_msg(parser, schc_pkt=All_01)
print(schc_parsed_01)

#Intermediate All_0
schc_parsed_0 = SCHCParser.parse_schc_msg(parser, schc_pkt=All_0)
print(schc_parsed_0)

#All_1
schc_parsed_1 = SCHCParser.parse_schc_msg(parser, schc_pkt=All_1)
print(schc_parsed_1)

#Compress packets
schc_parsed_comp = SCHCParser.parse_schc_msg(parser, schc_pkt=compress_pkt)
print(schc_parsed_comp)