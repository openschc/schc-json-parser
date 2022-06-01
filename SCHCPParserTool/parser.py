import SCHCPParserTool
from SCHCPParserTool.compr_core import * 
from SCHCPParserTool.compr_parser import * 
from SCHCPParserTool.gen_bitarray import BitBuffer
from SCHCPParserTool import gen_rulemanager as RM
from SCHCPParserTool import frag_msg as FM

from Cryptodome.Hash import CMAC as cmac
from Cryptodome.Cipher import AES

import json
import binascii
from scapy.all import *

class SCHCParser:

    def __init__(self):
        self.rule_file = "SCHCPParserTool/lorawan.json"
        self.device_id = "lorawan:1122334455667788"
        self.deveui = "1122334455667788"
        self.appskey = "00AABBCCDDEEFF00AABBCCDDEEFFAABB"
        self.rm = RM.RuleManager()
        self.rm.Add(file=self.rule_file)

    def changeDevEUI (self, DevEUI = None):
        self.deveui = DevEUI
        self.device_id = "lorawan:" + DevEUI
        self.rm.change_device_id(self.device_id)

    def changeAppSKey (self, AppSKey = None):
        self.appskey = AppSKey
        
    def getdeviid (AppSKey, DevEUI):
        cobj = cmac.new(bytes.fromhex(AppSKey), ciphermod=AES)
        cobj.update(bytes.fromhex(DevEUI))
        res = cobj.hexdigest()
        iid = res[0:16]

        dprint(iid)
        return iid

    def generateIPv6UDP(self, comp_ruleID, DevEUI, AppSKey, dev_prefix, ipv6_dst, udp_data):

        DevEUI = self.deveui
        AppSKey = self.appskey

        rule = self.rm.FindRuleFromRuleID(device=self.device_id, ruleID=comp_ruleID)

        #print(rule[T_COMP])
        for e in rule[T_COMP]:
            if e[T_FID] == 'IPV6.TC':
                tc = e[T_TV]
            if e[T_FID] == 'IPV6.FL':
                fl = e[T_TV]
            if e[T_FID] == 'IPV6.NXT':
                nh = e[T_TV]
            if e[T_FID] == 'IPV6.HOP_LMT':
                hl = e[T_TV]
            if e[T_FID] == 'UDP.DEV_PORT':
                sport = e[T_TV]
            if e[T_FID] == 'UDP.APP_PORT':
                dport = e[T_TV]


        iid  = SCHCParser.getdeviid(AppSKey=AppSKey, DevEUI=DevEUI)

        ipv6 = IPv6()
        ipv6.src = dev_prefix + str(iid)[0:4] + ":" + str(iid)[4:8] + ":" + str(iid)[8:12] + ":" +str(iid)[12:16]
        ipv6.dst = ipv6_dst
        ipv6.tc = tc
        ipv6.fl = fl
        ipv6.nh = nh
        ipv6.hl = hl

        udp = UDP()
        udp.sport = sport
        udp.dport = dport

        dprint ("dev_prefix", dev_prefix, " ipv6_dst ", ipv6_dst, " tc ", tc, " fl ", fl, " nh ", nh, " hl ", hl, sport, dport )
        
        ipv6_udp = ipv6/udp/udp_data

        return bytes(ipv6_udp)

    def bytes_needed(value):
        b = math.ceil(value/8) 
        return b

    def parse_schc_msg(self, schc_pkt, appskey=None, ruleID=None, chk_sum = None, udp_len = None):

        #if ruleID then add 8 bits at first before BitBuffer
        if ruleID is not None:
            schc_pkt = ruleID + schc_pkt

        schc_bbuf = BitBuffer(schc_pkt)
        rule = self.rm.FindRuleFromSCHCpacket(schc=schc_bbuf, device=self.device_id)

        if rule == None:
            print("rule not found")
            return None

        ruleid_value = rule[T_RULEID]
        ruleid_length = rule[T_RULEIDLENGTH]

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
            #print(payload)
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
                residue = schc_bbuf.get_bits_as_buffer(nb_bits=schc_bbuf._rpos-8, position=8)
                resi_len = residue._wpos

                residue_hex=binascii.hexlify(residue._content).decode('ascii')
                length = len(residue_hex)*4
                residue = f'{int(residue_hex, base=16):0>{length}b}'[0:resi_len]

                dprint(residue, resi_len) 
                schc_len = SCHCParser.bytes_needed(resi_len) + 1 # Rule is on 1 byte
                data = binascii.hexlify(schc_pkt[schc_len:]).decode('ascii')
                data_len = len(schc_pkt[schc_len:])

                keys = list(parsed_pkt.keys())
                values = list(parsed_pkt.values())

                for i, value in enumerate(values): # convert bytes to hexa 
                    if isinstance(value[0], bytes):
                        values[i][0] =  binascii.hexlify(value[0]).decode('ascii')

                comp = {}
                comp.update({"Residue": residue})
                comp.update({"ResidueLength": resi_len})

                comp.update({"Data": data})
                comp.update({"DataLength": data_len})

                for i, key in enumerate(keys):
                    try:
                        if YANG_ID[key[0]][1] == "fid-udp-length":
                            comp.update({YANG_ID[key[0]][1]: udp_len})
                        elif YANG_ID[key[0]][1] == "fid-udp-checksum":
                            comp.update({YANG_ID[key[0]][1]: chk_sum})
                        else:
                            comp.update({YANG_ID[key[0]][1]: values[i][0]})
                    except:
                        comp.update({keys[i][0]: values[i][0]})

                x = { "RuleIDValue":ruleid_value, 
                      "RuleIDLength":ruleid_length,
                      "Compression":comp
                }
      
        y = json.dumps(x)

        return y

    def genrate_schc_msg(self, packet, hint = {"RuleIDValue": 101}):

        t_dir = T_DIR_UP
        parser = Parser(self)
        comp = Compressor(self)

        # We parse the packet
        parsed_packet, residue, parsing_error = parser.parse(packet, t_dir, layers=["IPv6", "UDP"])

        # We search for a rule that matches the packet:

        rule, self.device_id = self.rm.FindRuleFromPacket(parsed_packet, direction=t_dir)
        if rule == None:
            print("Rule does not match packet")
            return None, None

        ruleid_value = rule[T_RULEID]

        if ruleid_value == hint["RuleIDValue"]:
            if T_COMP in rule:
                # Apply compression rule
                schc_packet = comp.compress(rule, parsed_packet, residue, t_dir)
                vec = binascii.hexlify(packet).decode('ascii')
                chk_sum = vec[92:96]
                udp_len = vec[88:92]
                json = self.parse_schc_msg(schc_packet._content, chk_sum = chk_sum, udp_len = udp_len)
            if T_FRAG in rule:
                # To be done
                return None, None
        else:
            print("Rule in packet does not match hint")
            return None, None
        dprint (schc_packet._content)
        return json, binascii.hexlify(schc_packet._content)
