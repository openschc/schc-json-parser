from SCHCPParserTool.parser import SCHCParser

parser = SCHCParser()
DevEUI = '1122334455667799'
parser.changeDevEUI (DevEUI=DevEUI)

oldrule_id = 101
new_ruleid = 16
parser.change_ruleid (oldrule_id, new_ruleid)
parser.rm.Print()

