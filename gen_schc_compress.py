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

# Now, we will define the parameters necessary to create the SCHC Packet

comp_ruleID = 101
dev_prefix = "fe80::" 
app_prefix = "fe80::" 

json = parser.generate_schc_comp(comp_ruleID, dev_prefix, app_prefix)

print(json)

comp_ruleID = 100

dev_prefix = "Aaaa::"
app_prefix = "Cccc::"
json = parser.generate_schc_comp(comp_ruleID, dev_prefix, app_prefix)

print(json)
