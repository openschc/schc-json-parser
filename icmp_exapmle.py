from SCHCPParserTool.parser import SCHCParser

# Examples with icmp 

device_id = "udp:54.37.158.10:8888"

# Some SCHC Messages in bytearray format:

all0_noack_a = b'\x01\xa0,@\x00\x00\x00\x1b\x03\xa0\xe0\x00\x00\x00\x00\x02\x02"Bb\x82\xa2\xc2\xe3\x03' # NoAck All-0
all0_noack_b = b'\x01\xa0#Cc\x83\xa3\xc3\xe4\x04$Dd\x84\xa4\xc4\xe5\x05%Ee\x85\xa5\xc5\xe6' # NoAck All-0
all1_noack = b'\x01\xa7\x9c\xe5E\x11\x06' # NoAck All-1

schc_compressed = b'\xc4\x00\x28\x3a\x00\x60\x44\x40\x00\x00\x00\x00\x00\x00\x02\x76\x60\x2c\x00\x00\x20\x00\x20\x40\x60\x80\xa0\xc0\xe1\x01\x20'
all0_AoE = b'\x01\x80\r\x88\x00Pt\x00\xc0\x88\x80\x00\x00\x00\x00\x00\x00\x04\xec\xc0W\x00\x00F\xa0$\x18\x80\x00\x00\x00./\xc3\x00\x00\x00\x00\x00\x04\x04D\x84\xc5\x05E\x85\xc6\x06F\x86\xc7\x07G\x87\xc8\x08H\x88\xc9\tI\x89\xca\nJ\x8a\xcb\x0bK\x8b\xcc\x0cL\x8c'
sender_abort_AoE = b'\x01\x87\xfe'

#Create a parser 
parser = SCHCParser()

#Indicate the rule in .json
parser.rule_file = "icmp3.json"
parser.rm.Add(file=parser.rule_file)

#Parse the SCHC Packet
JSON_File = SCHCParser.parse_schc_msg(parser, schc_pkt = all0_noack_a)
print(JSON_File)