from SCHCPParserTool.compr_core import * 
from SCHCPParserTool.compr_parser import * 
from SCHCPParserTool.gen_bitarray import BitBuffer
from SCHCPParserTool import gen_rulemanager as RM
from SCHCPParserTool import frag_msg as FM
import json
import binascii

class Parser:

    def __init__(self):
        self.rule_file = "icmp3.json"
        self.rm = RM.RuleManager()
        self.rm.Add(file=self.rule_file)
   
    def parse_schc_msg(self, schc_pkt, device_id, appskey=None, ruleID=None):

        #if ruleID then add 8 bits at first before BitBuffer
        schc_bbuf = BitBuffer(schc_pkt)
        rule = self.rm.FindRuleFromSCHCpacket(schc=schc_bbuf, device=device_id)
        ruleid_value = rule[T_RULEID]
        ruleid_length = rule[T_RULEIDLENGTH]
        #print(rule)
        if T_FRAG in rule:
            schc_frag = FM.frag_receiver_rx(rule, schc_bbuf)
            mode = rule[T_FRAG][T_FRAG_MODE]
            dtag_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_DTAG]
            fcn_length = None
            w_length = None
            if mode == "AckOnError":
                fcn_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN]
                w_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_W]
            tile_length = None
            if T_FRAG_TILE in rule[T_FRAG][T_FRAG_PROF]:
                tile_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_TILE]
            w_value = schc_frag.win
            dtag_value = schc_frag.dtag
            fcn_value = schc_frag.fcn
            payload = schc_frag.payload
            rcs = schc_frag.mic
            #schc_frag.bitmap
            all1_b = 2**rule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN]-1
            all1 = False
            if schc_frag.fcn == all1_b:
                all1 = True
            abort = schc_frag.abort
            ack = schc_frag.ack
            ack_request = schc_frag.ack_request
            #schc_frag.cbit
            #schc_frag.packet
            abort = schc_frag.abort
            print(payload)
            payload_hexa = None
            if payload is not None:
                payload_hexa = binascii.hexlify(payload._content).decode('ascii')
            rcs_hexa = None
            if rcs is not None:
                rcs_hexa = binascii.hexlify(rcs).decode('ascii')
   
            x = { "RuleIDValue":ruleid_value, 
                  "RuleIDLength":ruleid_length,
                  "Fragmentation":{
                    "mode": mode,
                    "WLength":w_length,
                    "DtagLength":dtag_length,
                    "FCNLength":fcn_length,
                    "TileLength":tile_length,
                    "WValue":w_value,
                    "DTagValue":dtag_value,
                    "FCNValue":fcn_value,
                    "Payload":payload_hexa,
                    "RCS":rcs_hexa,
                    "AllOne":all1,
                    "abort":abort,
                    "ack":ack,
                    "ack_req":ack_request,
                }        
            }

        else:
                decomp = Decompressor()
                parsed_pkt = decomp.decompress(schc=schc_bbuf, rule=rule, direction=T_DIR_UP)
                keys = list(parsed_pkt.keys())
                values = list(parsed_pkt.values())

                for i, value in enumerate(values): # convert bytes to hexa 
                    if isinstance(value[0], bytes):
                        values[i][0] =  binascii.hexlify(value[0]).decode('ascii')

                comp = {}
                for i, key in enumerate(keys):
                    try:
                        comp.update({YANG_ID[key[0]][1]: values[i][0]})
                        #print(YANG_ID[key[0]][1])
                    except:
                        comp.update({keys[i][0]: values[i][0]})
             
                x = { "RuleIDValue":ruleid_value, 
                      "RuleIDLength":ruleid_length,
                      "Compression":comp
                }
      
        y = json.dumps(x)

        return y