from SCHCPParserTool.parser import SCHCParser
import binascii

parser = SCHCParser()
parser.rule_file = "lorawan.json"
parser.rm.Add(file=parser.rule_file)
#parser.rm.Print() # To Check the Rule

All_01 =  b'\x14(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
All_0 = int = b'\x14\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00'
All_1 = b'\x14?\xa9\x8cX('

device_id = "lorawan:1122334455667788" #This should be the same as in the lorawan.json file

# We call the function to parse the fragments:

#First All_0
schc_parsed_01 = SCHCParser.parse_schc_msg(parser, schc_pkt=All_01, device_id=device_id)
print(schc_parsed_01)

#Intermediate All_0
schc_parsed_0 = SCHCParser.parse_schc_msg(parser, schc_pkt=All_0, device_id=device_id)
print(schc_parsed_0)

#All_1
schc_parsed_1 = SCHCParser.parse_schc_msg(parser, schc_pkt=All_1, device_id=device_id)
print(schc_parsed_1)

