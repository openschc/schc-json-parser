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

class SCHCParser:

    def __init__(self):
        self.rule_file = self.get_file_path()
        self.device_id = "lorawan:1122334455667788"
        self.deveui = "1122334455667788"
        self.appskey = "00AABBCCDDEEFF00AABBCCDDEEFFAABB"
        self.rm = RM.RuleManager()
        self.rm.Add(file=self.rule_file)
        self.iid  = SCHCParser.getdeviid(AppSKey=self.appskey, DevEUI=self.deveui)
        self.fcn_len = 6
        self.bitmap = None

    def get_file_path(self):
        target = "lorawan.json"
        initial_dir = os.getcwd()
        path = ''
        for root, _, files in os.walk(initial_dir):
            if target in files:
                path = os.path.join(root, target)
                break
        return path

    def changeDevEUI (self, DevEUI = None):
        self.deveui = DevEUI
        self.device_id = "lorawan:" + DevEUI
        self.rm.change_device_id(self.device_id)
        self.iid  = SCHCParser.getdeviid(AppSKey=self.appskey, DevEUI=self.deveui)

    def changeAppSKey (self, AppSKey = None):
        self.appskey = AppSKey
        self.iid  = SCHCParser.getdeviid(AppSKey=self.appskey, DevEUI=self.deveui)

    def change_ruleid (self, oldrule_id, new_ruleid):
        for a in self.rm._ctxt[0]['SoR']:
            if a['RuleID'] == oldrule_id:
                a['RuleID'] = new_ruleid
        
    def getdeviid (AppSKey, DevEUI):
        cobj = cmac.new(bytes.fromhex(AppSKey), ciphermod=AES)
        cobj.update(bytes.fromhex(DevEUI))
        res = cobj.hexdigest()
        iid = res[0:16]

        dprint(iid)
        return iid

    def generateIPv6UDP(self, comp_ruleID, dev_prefix = "fe80::" , ipv6_dst = "fe80::1", sport = 23616 , dport = 12400, udp_data = bytearray(50)):

        rule = self.rm.FindRuleFromRuleID(device=self.device_id, ruleID=comp_ruleID)

        print(len(udp_data))

        if rule is not None:
            #print(rule[T_COMP])
            if T_COMP in rule: 
                for e in rule[T_COMP]:
                    if e[T_FID] == 'IPV6.TC':
                        tc = e[T_TV]
                    elif e[T_FID] == 'IPV6.FL':
                        fl = e[T_TV]
                    elif e[T_FID] == 'IPV6.NXT':
                        nh = e[T_TV]
                    elif e[T_FID] == 'IPV6.HOP_LMT':
                        hl = e[T_TV]
                    elif e[T_FID] == 'UDP.DEV_PORT':
                        sport = e[T_TV]
                    elif e[T_FID] == 'UDP.APP_PORT':
                        dport = e[T_TV]
                    else:
                        pass

            elif T_NO_COMP in rule:
                tc = 0
                fl = 0
                nh = 17
                hl = 255
                sport = 23616
                dport = 12400
                dev_prefix = "fe80::"
                print("No compress")

            else:
                return None
        
        else:
            print("Rule does not exist")
            return None

        ipv6_src = dev_prefix + str(self.iid)[0:4] + ":" + str(self.iid)[4:8] + ":" + str(self.iid)[8:12] + ":" +str(self.iid)[12:16]
        udp_len = len(udp_data) + 8
        
        a = format(6, "04b") # 4
        b = format(tc, "08b")# 8
        c = format(fl, "020b")# 20

        first = int(a + b + c, 2).to_bytes(4,'big')

        d = format(udp_len, "016b") 
        e = format(nh, "08b") 
        f = format(hl, "08b") 

        second = int(d + e + f, 2).to_bytes(4,'big')


        ip_src = SCHCParser.getbytesipv6(ipv6_src)
        ip_dst = SCHCParser.getbytesipv6(ipv6_dst)

        ipv6_h = first + second + ip_src + ip_dst
        
        chsm = SCHCParser.get_checksum (self.iid, sport, dport, udp_data, dev_prefix = "fe80::", app_prefix = "fe80::" , app_iid = "::1", ipv6_dst = ipv6_dst)

        g = sport.to_bytes(2,'big')
        h = dport.to_bytes(2,'big')
        i = udp_len.to_bytes(2,'big')
        j = chsm.to_bytes(2,'big')

        udp = g + h + i + j + udp_data

        ipv6_udp = ipv6_h + udp 

        if comp_ruleID == 101:
            ipv6_h = first + second + ip_dst + ip_src
            udp = h + g + i + j + udp_data
            ipv6_udp = ipv6_h + udp
        
        return ipv6_udp

    def bytes_needed(value):
        b = math.ceil(value/8) 
        return b

    def getbytesipv6(ipv6_str):
        # type: (string) -> bytes
        nb_zeros = 8-len(ipv6_str.split(":")) + 1
        zero = 0
        ipv6_bytes = b""
        for value in ipv6_str.split(":"):
            if value != "":
                ipv6_bytes += int(value,16).to_bytes(2,'big')
            else:
                for i in range(nb_zeros):
                    ipv6_bytes += zero.to_bytes(2,'big')
        return ipv6_bytes     

    def compute_chksm(pkt):
        # type: (bytes) -> int
        if len(pkt) % 2 == 1:
            pkt += b"\0"
        s = sum(array("H", pkt))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        s = ~s

        if struct.pack("H", 1) != b"\x00\x01":  # big endian
            return ((s >> 8) & 0xff) | s << 8 & 0xffff
        else:
            return s

    def get_checksum (iid, sport, dport, udp_data, dev_prefix = "fe80::", app_prefix = "fe80::" , app_iid = "::1", ipv6_dst = None):

        ipv6_src = dev_prefix + str(iid)[0:4] + ":" + str(iid)[4:8] + ":" + str(iid)[8:12] + ":" +str(iid)[12:16]
        
        if ipv6_dst == None:
            ipv6_dst = app_prefix + app_iid

        protocol = 17
        udp_len = len(udp_data) + 8
        #print(ipv6_dst)
 
        a = SCHCParser.getbytesipv6 (ipv6_src)
        b = SCHCParser.getbytesipv6 (ipv6_dst)
        c = protocol.to_bytes(2,'big')
        d = udp_len.to_bytes(2,'big')
        pseudo_h = a + b + c + d
        udp_h = sport.to_bytes(2,'big') + dport.to_bytes(2,'big') + udp_len.to_bytes(2,'big')

        chksum = SCHCParser.compute_chksm(pseudo_h + udp_h)
        dprint("checksum", chksum)
        return chksum

    def get_void_bitmap(self):
        fcn_len = self.fcn_len
        bitmap = [0] * (2 ** (fcn_len)-1)
        return bitmap

    def get_lastpos(a): 
        l = len(a)
        for x in reversed(a):
            if x == 0:
                l -= 1
                continue
            else:
                print(x,l)
                break
        return l

    def get_bitmap_hex(a, fcn, w):
        a = a[w]
        missing = []
        if fcn == len(a):
            a = a[:SCHCParser.get_lastpos(a)]
        for idx, x in enumerate(a[:len(a)-fcn-1]):
            if x == 0:
                missing.append(idx)
        if len(missing) != 0:
            print(len(missing))
            bitmap_length = SCHCParser.bytes_needed(missing[-1]) 
            bitmap_str = "".join([str(_) for _ in a[:bitmap_length*8]])
            bValues = [bitmap_str[i:i+8] for i in range(0, len(bitmap_str), 8)]
            bitmap_bytearray = bytearray()
            for bValue in bValues:
                local_bytearray = int(bValue, 2).to_bytes(len(bValue) // 8, byteorder='big')
                bitmap_bytearray += local_bytearray
            print(bitmap_bytearray)
            return bitmap_bytearray
        else:
            return False

    def reassembly_tiles(self):
        payload = ""
        a = self.tiles
        last = SCHCParser.get_lastpos(a[-1]) 
        for idx, x in enumerate(a):
            if idx != len(a)-1:
                payload += "".join([str(_) for _ in a[idx][:]])
            else:
                payload += "".join([str(_) for _ in a[idx][:last]])

        return payload

    def reassembly(self, fragment = None, tiles_all1 = True):
        if self.bitmap is None:
            self.bitmap = [SCHCParser.get_void_bitmap(self)]
            self.tiles = [SCHCParser.get_void_bitmap(self)]

        # Get parameters from fragment:

        schc_frag = json.loads(fragment)
        w = schc_frag['Fragmentation']['WValue']
        fcn = schc_frag['Fragmentation']['FCNValue']
        nb_tiles = schc_frag['Fragmentation']['FragmentPayloadLength']//schc_frag['Fragmentation']['TileLength']
        frag_payload = schc_frag['Fragmentation']['FragmentPayload']
        SCHCParser.get_bitmap(self, bitmap = self.bitmap, 
                                    tiles = self.tiles,
                                    frag_payload = frag_payload,
                                    tiles_all1 = tiles_all1, 
                                    frags = None, w = w, 
                                    fcn = fcn, 
                                    nb_tiles = nb_tiles)
        # print(self.bitmap)
        # Check for missing tiles, if missing we get the bitmap in hexa to create the ACK
        bitmap_hex = SCHCParser.get_bitmap_hex(self.bitmap, fcn, w)
        if bitmap_hex == False and fcn == 63:
            payload = SCHCParser.reassembly_tiles(self)
            pay_hex = binascii.unhexlify(payload)
            print("start reassembly, payload:")
            print(payload)
            print("crc", binascii.crc32(pay_hex))
        else:
            # Create the falure ACK 
            print(bitmap_hex)
        return bitmap_hex

    def get_bitmap(self, bitmap = None, tiles = None, frag_payload = None, tiles_all1=False, frags = [], w = 0, fcn = 62, nb_tiles = 0):
        #print('w=',w)

        # Separate frag peyload into tiles
        fragment_tiles = [frag_payload[i:i+20] for i in range(0, len(frag_payload), 20)]
        #print("fragment_tiles",fragment_tiles)
        if fcn == len(bitmap[w]) - 1 : # First Fragment
            bitmap[w] [0:nb_tiles] = [1 for i in range(nb_tiles)]
            tiles[w] [0:nb_tiles - 1] = fragment_tiles
            #print ("first", 0, nb_tiles)
        elif fcn == len(bitmap[w]): 
            if tiles_all1 == False: # Last Fragment without tiles on last fragment
                #Call RCS
                #print ('reassembly and RCS computation - no tiles in all1')
                return bitmap
            else:
                init = SCHCParser.get_lastpos(bitmap[w])
                frag_payload = frag_payload [8:]
                fragment_tiles = [frag_payload[i:i+20] for i in range(0, len(frag_payload), 20)]
                last = init + nb_tiles
                bitmap[w] [init : last] = [1 for i in range(nb_tiles)]
                tiles[w] [init : last] = fragment_tiles
                #print ('Reassembly and RCS computation - tiles in all1')
                # Call RCS
        else:
            init = len(bitmap[w]) - fcn - 1
            last = len(bitmap[w]) - fcn  + nb_tiles - 1
            if last < len(bitmap[w]): # Intermediate Fragment
                bitmap[w] [init : last] = [1 for i in range(nb_tiles)]
                #print("lens --> ", len(tiles[w] [init : last]), len(fragment_tiles))
                tiles[w] [init : last] = fragment_tiles
            else: # Fragment with info of two tiles
                last_a = len(bitmap[w])
                last_b = nb_tiles - (len(bitmap[w]) - init)
                bitmap[w] [init : last_a + 1] = [1 for i in range(len(bitmap[w]) - init)]
                tiles[w] [init : last_a + 1] = fragment_tiles[:len(bitmap[w]) - init]
                #Add a new bitmap / tiles vector
                bitmap = [bitmap[w], SCHCParser.get_void_bitmap(self)]
                tiles = [tiles[w], SCHCParser.get_void_bitmap(self)]
                bitmap[w + 1][: last_b] = [1 for i in range(last_b)]
                #print("lens", len(bitmap[1][0: last_b]), fragment_tiles[len(bitmap[w]) - init:])
                tiles[w + 1][: last_b] = fragment_tiles[len(bitmap[w]) - init:]
            #print (init , last)
        self.bitmap = bitmap
        self.tiles = tiles
        print("tiles", tiles, len(tiles[0]))
        return bitmap

    def parse_schc_msg(self, schc_pkt, ruleID = None):

        #if ruleID then add 8 bits at first before BitBuffer

        if ruleID is not None:
            ruleID = ruleID.to_bytes(1, 'big')
            schc_pkt = ruleID + schc_pkt

        deviid = self.iid
        chk_sum = None

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
            #payload = schc_frag.payload
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
            schc_len = SCHCParser.bytes_needed(ruleid_length + w_length + fcn_length)
            payload = binascii.hexlify(schc_pkt[schc_len:]).decode('ascii')
            abort = schc_frag.abort
            payload_hexa = None
            if payload is not None:
                payload_hexa = payload
                payload_len = len(schc_pkt[schc_len:])
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
                    "FragmentPayload":payload_hexa,
                    "FragmentPayloadLength":payload_len,
                    "RCS":rcs_hexa,
                    "AllOne":all1,
                    "abort":abort,
                    "ack":ack,
                    "ack_req":ack_request,
                }
            }

        elif T_COMP in rule:
        
                decomp = Decompressor()
                parsed_pkt = decomp.decompress(schc=schc_bbuf, rule=rule, direction = T_DIR_UP)
                residue = schc_bbuf.get_bits_as_buffer(nb_bits=schc_bbuf._rpos-8, position=8)
                resi_len = residue._wpos

                residue_hex=binascii.hexlify(residue._content).decode('ascii')
                length = len(residue_hex)*4
                residue = f'{int(residue_hex, base=16):0>{length}b}'[0:resi_len]

                dprint(residue, resi_len) 
                schc_len = SCHCParser.bytes_needed(resi_len) + 1 # Rule is on 1 byte

                pad_len = schc_len*8-8 - resi_len
                padding = format(0, "0" + str(pad_len) + "b")
                
                data = binascii.hexlify(schc_pkt[schc_len:]).decode('ascii')
                data_len = len(schc_pkt[schc_len:])
                udp_len = data_len + 8
                ipv6_len = udp_len

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

                comp.update({"Padding": padding})
                comp.update({"PaddingLength": pad_len})

                for e in rule[T_COMP]:
                    if e[T_FID] == 'IPV6.TC':
                        tc = e[T_TV]
                        comp.update({YANG_ID[e[T_FID]][1]: tc})
                    elif e[T_FID] == 'IPV6.FL':
                        fl = e[T_TV]
                        comp.update({YANG_ID[e[T_FID]][1]: fl})
                    elif e[T_FID] == 'IPV6.NXT':
                        nh = e[T_TV]
                        comp.update({YANG_ID[e[T_FID]][1]: nh})
                    elif e[T_FID] == 'IPV6.HOP_LMT':
                        hl = e[T_TV]
                        comp.update({YANG_ID[e[T_FID]][1]: hl})
                    elif e[T_FID] == 'UDP.DEV_PORT':
                        sport = e[T_TV]
                        comp.update({YANG_ID[e[T_FID]][1]: sport})
                    elif e[T_FID] == 'UDP.APP_PORT':
                        dport = e[T_TV]
                        comp.update({YANG_ID[e[T_FID]][1]: dport})
                    else:
                        pass


                for i, key in enumerate(keys):
                    try:
                        if YANG_ID[key[0]][1] == "fid-udp-length":
                            comp.update({YANG_ID[key[0]][1]: udp_len})
                        elif YANG_ID[key[0]][1] == "fid-udp-checksum":
                            comp.update({YANG_ID[key[0]][1]: chk_sum})
                        elif YANG_ID[key[0]][1] == "fid-ipv6-payloadlength": 
                            comp.update({YANG_ID[key[0]][1]: ipv6_len})
                        elif YANG_ID[key[0]][1] == "fid-ipv6-deviid":
                            comp.update({YANG_ID[key[0]][1]: deviid})
                        else:
                            comp.update({YANG_ID[key[0]][1]: values[i][0]})
                    except:
                        comp.update({keys[i][0]: values[i][0]})

                chk_sum = SCHCParser.get_checksum (self.iid, 
                                                   comp["fid-udp-dev-port"],
                                                   comp["fid-udp-app-port"],
                                                   bytearray(data_len),
                                                   dev_prefix = comp["fid-ipv6-devprefix"][0:4]+"::",
                                                   app_prefix = comp["fid-ipv6-appprefix"][0:4]+"::",
                                                   app_iid = comp["fid-ipv6-appiid"],
                                                   )                
                comp.update({YANG_ID[key[0]][1]: chk_sum})
                #print(chk_sum)

                x = { "RuleIDValue":ruleid_value, 
                      "RuleIDLength":ruleid_length,
                      "Compression":comp
                }
        else: # "NO COMPRESSION"

            parser = Parser(self)
            t_dir = T_DIR_UP

            # We parse the IPv6 Packet
            parsed_pkt, residue, parsing_error = parser.parse(schc_pkt[1:], t_dir, layers=["IPv6", "UDP"])

            keys = list(parsed_pkt.keys())
            values = list(parsed_pkt.values())

            nocomp = {}

            for i, value in enumerate(values): # convert bytes to hexa 
                if isinstance(value[0], bytes):
                    values[i][0] =  binascii.hexlify(value[0]).decode('ascii')
                        
            for i, key in enumerate(keys):
                nocomp.update({YANG_ID[key[0]][1]: values[i][0]})

            print (nocomp["fid-udp-length"])

            # Header and IID velidation:

            tc = 0 # Not tested
            fl = 0 # Not Tested
            nh = 17
            hl = 255 # Not Tested
            sport = 23616
            dport = 12400
            dev_prefix = "fe80::"
            app_prefix = "fe80::"
            prefix_l = "fe80000000000000"
            app_iid = "::1"
            app_iid_l = "0000000000000001" 
            udp_len = nocomp["fid-udp-length"]
            ipv6_pay_len = udp_len
            udp_data = bytearray(udp_len-8) # bytearray full of zeros
            chk_sum = SCHCParser.get_checksum(self.iid, sport, dport, udp_data, dev_prefix = dev_prefix, app_prefix = app_prefix, app_iid = app_iid)

            dprint("chsm", chk_sum)

            for i, key in enumerate(keys):
                try:
                    if YANG_ID[key[0]][1] == "fid-ipv6-deviid":
                        dprint("iid", values[i][0], self.iid)
                        if values[i][0] == self.iid:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})
                    elif YANG_ID[key[0]][1] == "fid-udp-dev-port":
                        if values[i][0] == sport:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})
                    elif YANG_ID[key[0]][1] == "fid-udp-app-port":
                        if values[i][0] == dport:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})  
                    elif YANG_ID[key[0]][1] == "fid-udp-length":
                        #print ("udp_len_dut:",values[i][0])
                        if values[i][0] == udp_len:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})  
                    elif YANG_ID[key[0]][1] == "fid-udp-checksum":
                        if values[i][0] == chk_sum:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})  
                    elif YANG_ID[key[0]][1] == "fid-ipv6-payloadlength":
                        if values[i][0] == ipv6_pay_len:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})  
                    elif YANG_ID[key[0]][1] == "fid-ipv6-nextheader":
                        if values[i][0] == nh:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})  
                    elif YANG_ID[key[0]][1] == "fid-ipv6-devprefix": 
                        if values[i][0] == prefix_l:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})  
                    elif YANG_ID[key[0]][1] == "fid-ipv6-appprefix":
                        if values[i][0] == prefix_l:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})  
                    elif YANG_ID[key[0]][1] == "fid-ipv6-appiid": 
                        if values[i][0] == app_iid_l:
                            nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                        else:
                            nocomp.update({YANG_ID[key[0]][1]: "Not valid"})  
                    else:
                        nocomp.update({YANG_ID[key[0]][1]: values[i][0]})
                except:
                        comp.update({keys[i][0]: values[i][0]})

            x = { "RuleIDValue":ruleid_value, 
                  "RuleIDLength":ruleid_length,
                  "NoCompression":nocomp
            }

        y = json.dumps(x)

        return y

    def generate_schc_msg(self, packet, hint = {"RuleIDValue": 101}):
        # packet -> IPv6/UDP in bytes
        # hint -> JSON format

        t_dir = T_DIR_UP
        t_dir = hint["Direction"]
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
                json = self.parse_schc_msg(schc_packet._content)
            if T_FRAG in rule:
                # To be done
                return None, None
        else:
            print("Rule in packet does not match hint")
            return None, None
        dprint (schc_packet._content)
        return json, schc_packet._content

    def generate_schc_comp(self, RuleID, dev_prefix, app_prefix):

        rule = self.rm.FindRuleFromRuleID(device=self.device_id, ruleID=RuleID)

        if rule == None:
            print("RuleID not valid")
            return None
            
        if T_COMP in rule:
            ipv6_dst = app_prefix + "1"
            ipv6_packet = SCHCParser.generateIPv6UDP(self,
                                                     comp_ruleID= RuleID, 
                                                     dev_prefix = dev_prefix, 
                                                     ipv6_dst = ipv6_dst,  
                                                     udp_data = bytearray(50))

            JSON_Hint = {"RuleIDValue": RuleID}
            dict, schc_pkt = SCHCParser.generate_schc_msg(self, packet = ipv6_packet, hint=JSON_Hint)

            if dict != None :
                parsed = json.loads(dict) 
                
                residue = parsed["Compression"]["Residue"]
                resi_len = parsed["Compression"]["ResidueLength"]
                padding = parsed["Compression"]["Padding"]
                pad_len = parsed["Compression"]["PaddingLength"]

                comp = {}

                comp.update({"Residue": residue})
                comp.update({"ResidueLength": resi_len})
                comp.update({"Padding": padding})
                comp.update({"PaddingLength": pad_len})
            
            else:
                print("RuleID is a compression rule but args does not match with the rule")
                return None
        else:
            print("Not a compression RuleID")
            return None 

        return comp
