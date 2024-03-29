from numpy import pad
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
        # Variables specific for reassembly
        self.fcn_len = 6
        self.bitmap = None
        self.all1_received = False
        self.rcs = None
        self.all1_fragment = ""
        self.tiles_all1 = True

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

    def generateIPv6UDP(self, comp_ruleID, 
                        dev_prefix = "fe80::" , 
                        ipv6_dst = "fe80::1", 
                        sport = 23616 , 
                        dport = 12400, 
                        udp_data = bytearray(50),
                        dir = T_DIR_UP):

        rule = self.rm.FindRuleFromRuleID(device=self.device_id, ruleID=comp_ruleID)

        dprint(len(udp_data))

        if comp_ruleID == 101:
            dir = T_DIR_DW

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
                dprint("No compress")
            else:
                return None
        
        else:
            dprint("Rule does not exist")
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

        if dir == T_DIR_DW:
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
        #print("l=", l)
        for x in reversed(a):
            if x == 0:
                l -= 1
                continue
            else:
                #print(x,l)
                break
        return l

    def get_lastpos_compressed(a): 
        l = len(a)
        #print("l=", l)
        for x in reversed(a):
            if x == 1:
                l -= 1
                continue
            else:
                #print(x,l)
                break
        return l

    def tiles_missing(self, fcn = 62, w = 0, ack_req = False):
        #print('bitmap', self.bitmap)
        
        missing = [[] for x in range(0,len(self.bitmap))] 
        w_all = []
        #print ("fcn , w ", fcn, w)
        for idx_a, _ in enumerate(self.bitmap):
            a = self.bitmap[idx_a]
            if idx_a == w:
                limit = len(a)-fcn-1
                if fcn == len(self.bitmap[0]) or ack_req:
                    limit = SCHCParser.get_lastpos(a)
            else : 
                if len(self.bitmap) - 1 <= w:
                    limit = len(a)
                else:
                    limit = SCHCParser.get_lastpos(a)
            dprint('limit', limit)
            
            for idx_b, x in enumerate(a[:limit]):
                if x == 0:
                    w = idx_a
                    w_all.append(idx_a)
                    missing[w].append(idx_b)
        
        dprint("min w_all", min(w_all, default=0))
        dprint("bitmap",self.bitmap)
        dprint("missing",missing)
        dprint("w_all",w_all)

        nb_missing = 0
        for x in missing:
            nb_missing =  nb_missing + sum(x)

        if nb_missing != 0:
            return min(w_all, default=0), True
        else:
            return w, False

    def get_ack_hex(bitmap = [], wc = "", fcn = 62, w = 0, faux = False, bad_rcs = False, tiles_missing = True):

        a = bitmap[w]
        if fcn == len(a):
            a = a[:SCHCParser.get_lastpos(a)]
        
        # Add ack header wc to the bitmap
        wc_list = []
        ack_list = wc_list[:0] = wc
        a = list(map(int, ack_list)) + a
        padding = ""

        #print("ack header + compressed bitmap", a)
        if tiles_missing or bad_rcs:
            #print(len(missing))
            last = SCHCParser.get_lastpos_compressed(a)
            #print("a", a)
            #print('last', last)
            bitmap_length = SCHCParser.bytes_needed(last) 
            #print("bitmap_length",bitmap_length)
            bitmap_str = "".join([str(_) for _ in a[:bitmap_length*8]])
            #print(bitmap_str)
            bValues = [bitmap_str[i:i+8] for i in range(0, len(bitmap_str), 8)]
            #Add zeros as padding
            if len(bValues[-1]) != 8 : 
                padding = format(0, "0" + str(8 - len(bValues[-1])) + "b") # padding_len
                bValues[-1] = bValues[-1] + padding
            bitmap_bytearray = bytearray()
            # Convert bin to bytearray 8 by 8
            for bValue in bValues:
                #print ("bValue",bValue)
                local_bytearray = int(bValue, 2).to_bytes((len(bValue) + 7) // 8, byteorder='big')
                bitmap_bytearray += local_bytearray
            return bitmap_str[3:], padding, bitmap_bytearray

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

        # Initialize values to create ACK later
        self.tiles_all1 = True
        rcs_check = True
        c = 1
        
        # Create a new bitmap and tiles vectors if not done already
        if self.bitmap is None:
            self.bitmap = [SCHCParser.get_void_bitmap(self)]
            self.tiles = [SCHCParser.get_void_bitmap(self)]

        # Get parameters from fragment:
        schc_frag = json.loads(fragment)
        ruleid_value = schc_frag['RuleIDValue']
        ruleid_length = schc_frag["RuleIDLength"]
        w_length = schc_frag['Fragmentation']["WLength"]
        w_value = schc_frag['Fragmentation']['WValue']
        dtag_value = schc_frag['Fragmentation']['DTagValue']
        dtag_length = schc_frag['Fragmentation']['DtagLength']
        rcs = schc_frag['Fragmentation']["RCS"]
        fcn = schc_frag['Fragmentation']['FCNValue']
        nb_tiles = schc_frag['Fragmentation']['FragmentPayloadLength']//schc_frag['Fragmentation']['TileLength']
        frag_payload = schc_frag['Fragmentation']['FragmentPayload']
        ack_req = schc_frag['Fragmentation']["ack_req"]

        SCHCParser.get_bitmap(self, bitmap = self.bitmap, 
                                    tiles = self.tiles,
                                    frag_payload = frag_payload,
                                    tiles_all1 = tiles_all1, 
                                    frags = None, w = w_value, 
                                    fcn = fcn, 
                                    nb_tiles = nb_tiles)
        #print(self.bitmap)

        # Save the all1 for later if needed
        if fcn == len(self.bitmap[0]):
            self.all1_received = True
            self.rcs = rcs
            self.all1_fragment = fragment

        # Check for missing tiles
        w_miss, tiles_missing = SCHCParser.tiles_missing(self, fcn=fcn, w = w_value, ack_req = ack_req)
        dprint("w_miss, tiles_missing", w_miss, tiles_missing)
        # There is no aparent tiles missing and we receive an all1
        if tiles_missing == False and fcn == len(self.bitmap[0]):
            payload = SCHCParser.reassembly_tiles(self)
            pay_hex = binascii.unhexlify(payload)
            rcs_pay = binascii.crc32(pay_hex)
            rcs_int = int(rcs, 16)
            rcs_check = rcs_pay == rcs_int
            c = 1
            dprint("RCS check", rcs_pay, rcs_int, rcs_check)

            if rcs_check == False:
                payload = ""
                c = 0
                if tiles_all1: #delete tile and bitmap position 
                    SCHCParser.fix_bitmap(self, nb_tiles, w_value)

            # We create the ack
            ack = SCHCParser.generate_schc_ack (
                self = self,
                ruleid_value = ruleid_value, 
                ruleid_length = ruleid_length, 
                dtag_value = dtag_value, 
                dtag_length = dtag_length, 
                w_length = w_length,
                w_value = w_miss, 
                c = c, 
                rcs_check = rcs_check,
                tiles_missing = tiles_missing,
                payload = payload)
            return ack

        if tiles_missing == True and fcn == len(self.bitmap[0]) and tiles_all1:
            SCHCParser.fix_bitmap(self, nb_tiles, w_value)
            rcs_check = False
            c = 0

        if tiles_missing == True:
            # Put the c bit to 0 indicating that there are missing tiles  
            c = 0
            ack = SCHCParser.generate_schc_ack (
                self = self,
                ruleid_value = ruleid_value, 
                ruleid_length = ruleid_length, 
                dtag_value = dtag_value, 
                dtag_length = dtag_length, 
                w_length = w_length,
                w_value = w_miss, 
                c = c, 
                rcs_check = rcs_check,
                tiles_missing = tiles_missing)
            return ack

        if ack_req == True and tiles_missing == False and rcs_check == False:
            # Put the c bit to 0 indicating that there are missing tiles  
            dprint("here bitmap", self.bitmap)
            c = 0
            ack = SCHCParser.generate_schc_ack (
                self = self,
                ruleid_value = ruleid_value, 
                ruleid_length = ruleid_length, 
                dtag_value = dtag_value, 
                dtag_length = dtag_length, 
                w_length = w_length,
                w_value = w_miss, 
                c = c, 
                rcs_check = rcs_check,
                tiles_missing = tiles_missing,
                ack_req = ack_req)

            dprint ('ack', ack)
            return ack

        if ack_req == True and tiles_missing == False:
            c = 0
            rcs_check = False
            ack = SCHCParser.generate_schc_ack (
                self = self,
                ruleid_value = ruleid_value, 
                ruleid_length = ruleid_length, 
                dtag_value = dtag_value, 
                dtag_length = dtag_length, 
                w_length = w_length,
                w_value = w_miss, 
                c = c, 
                rcs_check = rcs_check,
                tiles_missing = tiles_missing,
                ack_req = ack_req)

            dprint ('ack', ack)
            return ack

        # The all1 has been already received and we receive another packet after, we re-inject the all1:
        if self.all1_received and fcn != len(self.bitmap[0]):
            frag = self.all1_fragment
            ack = SCHCParser.reassembly(self, fragment = frag, tiles_all1 = tiles_all1)
            return ack
        return None

    def generate_schc_ack(self,
                          ruleid_value = None, 
                          ruleid_length = None, 
                          dtag_value = None, 
                          dtag_length = None, 
                          fcn = None,
                          w_length = None,
                          w_value = None, c = 1 , 
                          rcs_check = True,
                          tiles_missing = False,
                          payload = "",
                          ack_req = False):
        ack = ""
        bitmap_str = ""
        padding = None
        w_b = format(w_value, "02b") # 2
        c_b = format(c, "01b") # 1
        len_wc = len (w_b + c_b)
        wc = w_b + c_b
        
        if rcs_check == True:
            akc_header_len = SCHCParser.bytes_needed(len_wc)
            padding = format(0, "0" + str(akc_header_len*8 - len_wc) + "b") # padding_len
            ack = int(w_b + c_b + padding, 2).to_bytes(akc_header_len,'big')

        if rcs_check == False and tiles_missing == False:
            bitmap_str, padding,  ack = SCHCParser.get_ack_hex(bitmap=self.bitmap,
                                         wc = wc,
                                         fcn = fcn, 
                                         w = w_value, 
                                         bad_rcs = True, 
                                         tiles_missing = False)
        if tiles_missing:
            bitmap_str, padding, ack = SCHCParser.get_ack_hex(bitmap = self.bitmap,
                                         wc = wc,
                                         fcn = fcn, 
                                         w = w_value, 
                                         bad_rcs = True, 
                                         tiles_missing = True)
        if ack_req:
            bitmap_str, padding, ack = SCHCParser.get_ack_hex(bitmap = self.bitmap,
                                         wc = wc,
                                         fcn = fcn, 
                                         w = w_value, 
                                         bad_rcs = rcs_check, 
                                         tiles_missing = True)

        ack_hexa = str(binascii.hexlify(ack))
        #print("ack_bin, ack_hex", w_b + c_b + padding, binascii.hexlify(ack))

        x = {"AckHexa":ack_hexa[2:-1],
             "RuleIDValue":ruleid_value, 
             "RuleIDLength": ruleid_length,
             "DTagValue":dtag_value,
             "DtagLength":dtag_length,
             "WLength": w_length,
             "WValue": w_value,
             "Cbit": c,
             "Bitmap" : bitmap_str,
             "Padding": padding,
             "Payload": payload,
            }

        y = json.dumps(x)
        return y

    def get_bitmap(self, bitmap = None, tiles = None, frag_payload = None, tiles_all1=False, frags = [], w = 0, fcn = 62, nb_tiles = 0):
        # Separate frag payload into tiles
        fragment_tiles = [frag_payload[i:i+20] for i in range(0, len(frag_payload), 20)]
        #print("len_bitmap", len(bitmap))
        #print("w", w)
        
        if w + 1 > len(bitmap): # The index (w) exeed the length of the current bitmap
            #print("FCN", fcn, w, len(bitmap)-1)
            bitmap = [bitmap[w-1], SCHCParser.get_void_bitmap(self)]
            tiles = [tiles[w-1], SCHCParser.get_void_bitmap(self)]
        if fcn == len(bitmap[w]) - 1 : # First Fragment
            bitmap[w] [0:nb_tiles] = [1 for i in range(nb_tiles)]
            tiles[w] [0:nb_tiles - 1] = fragment_tiles
            #print ("first", 0, nb_tiles)
        elif fcn == len(bitmap[w]):  #Last Fragment
            if tiles_all1 == False: # Last Fragment without tiles on last fragment
                # TODO Call RCS
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
        else: #intermediate fragment
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
                #Add a new bitmap / tiles vector if not already done
                #print( w + 1 , len(bitmap))
                if w + 2 > len(bitmap):
                    bitmap = [bitmap[w], SCHCParser.get_void_bitmap(self)]
                    tiles = [tiles[w], SCHCParser.get_void_bitmap(self)]
                bitmap[w + 1][: last_b] = [1 for i in range(last_b)]
                #print("lens", len(bitmap[1][0: last_b]), fragment_tiles[len(bitmap[w]) - init:])
                tiles[w + 1][: last_b] = fragment_tiles[len(bitmap[w]) - init:]
        self.bitmap = bitmap
        #print (self.bitmap)
        self.tiles = tiles
        #print("tiles", tiles, len(tiles[0]))
        return bitmap


    def fix_bitmap(self, nb_tiles = 0, w = 0) :
        #TODO verifier si w est bon avant
        #print("here?")
        a = self.bitmap
        b = self.tiles
        tiles_in_bitmap = sum(a[w])
        last = SCHCParser.get_lastpos(a[w])
        #print(tiles_in_bitmap)
        if tiles_in_bitmap >= nb_tiles:
            #print(last)
            a[w][last - nb_tiles:last] = [0 for i in range(nb_tiles)]
            b[w][last - nb_tiles:last] = [0 for i in range(nb_tiles)]
        else:
            a[w][:last] = [0 for i in range(last)]
            b[w][:last] = [0 for i in range(last)]
            remaining = nb_tiles - last
            a[w-1][len(a[w]) - remaining:] = [0 for i in range(remaining)]
            b[w-1][len(b[w]) - remaining:] = [0 for i in range(remaining)]
        self.bitmap = a
        self.tiles = b

    def parse_schc_msg(self, schc_pkt, ruleID = None, dir = None, payload_aa = "", rcs_aa=0):

        #if ruleID then add 8 bits at first before BitBuffer
        if ruleID is not None:
            ruleID = ruleID.to_bytes(1, 'big')
            schc_pkt = ruleID + schc_pkt
        if dir == None : 
            dir = T_DIR_UP

        schc_bbuf = BitBuffer(schc_pkt)
        deviid = self.iid
        chk_sum = None
        recever_abort = ""
        payload_len = ""
        rcs_hexa = ""
        all1 = False
        ack_request = False
        c_value = ''

        rule = self.rm.FindRuleFromSCHCpacket(schc=schc_bbuf, device=self.device_id)

        dprint("schc_bbuf", schc_bbuf.display)
        if rule == None:
            print("rule not found")
            return None

        ruleid_value = rule[T_RULEID]
        ruleid_length = rule[T_RULEIDLENGTH]

        if T_FRAG in rule:
            mode = rule[T_FRAG][T_FRAG_MODE]
            dtag_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_DTAG]
            fcn_length = None
            w_length = 0
            if mode == "AckOnError":
                fcn_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN]
                w_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_W]
            tile_length = None
            if T_FRAG_TILE in rule[T_FRAG][T_FRAG_PROF]:
                tile_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_TILE]
            dtag_value = None

            if dir == T_DIR_UP and mode == "AckOnError":
                schc_frag = FM.frag_receiver_rx(rule, schc_bbuf)
                if rule[T_FRAG][T_FRAG_PROF][T_FRAG_DTAG] != 0:
                    dtag_value = schc_frag.dtag
                w_value = schc_frag.win
                fcn_value = schc_frag.fcn
                all1_b = 2**rule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN]-1
                all1 = False
                rcs = None
                if schc_frag.fcn == all1_b:
                    all1 = True
                    rcs = schc_frag.mic   
                    #print("rcs=", rcs)  
                payload = schc_frag.payload
                    #schc_frag.bitmap
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
                    rcs_hexa = binascii.hexlify(rcs.to_bytes(4, 'big')).decode('ascii')

            if dir == T_DIR_DW and mode == "AckOnError": #  abort
                w_value = None
                dtag_value = None
                fcn_value = None
                payload_hexa = None
                AllOne = False
                abort = True
                ack = False
                ack_req = False
                recever_abort = binascii.hexlify(schc_pkt[1:]).decode('ascii')

            if dir == T_DIR_UP and mode == "AckAlways": # ACK or abort:
                
                bytes_as_bits = ''.join(format(byte, '08b') for byte in schc_pkt[1:])
                w_value = bytes_as_bits[0]
                c_value = bytes_as_bits[1]
                ack = True # TODO
                fcn_value = None
                payload_hexa = None
                abort = False # TODO
                if len(bytes_as_bits) == 16:
                    abort = True # TODO
                    ack = False

            if dir == T_DIR_DW and mode == "AckAlways":
                    fcn_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_FCN]
                    w_length = rule[T_FRAG][T_FRAG_PROF][T_FRAG_W]
                    schc_frag = FM.frag_receiver_rx(rule, schc_bbuf)
                    tile_length = None
                    w_value = schc_frag.win
                    if rule[T_FRAG][T_FRAG_PROF][T_FRAG_DTAG] != 0:
                        dtag_value = schc_frag.dtag
                    fcn_value = schc_frag.fcn

                    payload_hexa = payload_aa
                    payload_len = len(payload_aa)
                    rcs_hexa = binascii.hexlify(rcs_aa.to_bytes(4, 'big')).decode('ascii') 
                    all1 = False
                    if fcn_value == 1:
                        all1 = True
                    abort = False
                    ack = False
                    ack_request = False
                    recever_abort = False

                    #print('w_value', w_value)

            x = { "FragmentHexa": binascii.hexlify(schc_pkt[1:]).decode('ascii'),
                  "RuleIDValue":ruleid_value, 
                  "RuleIDLength":ruleid_length,
                  "Fragmentation":{
                    "mode": mode,
                    "WLength":w_length,
                    "DtagLength":dtag_length,
                    "FCNLength":fcn_length,
                    "TileLength":tile_length,
                    "WValue":w_value,
                    "CValue":c_value,
                    "DTagValue":dtag_value,
                    "FCNValue":fcn_value,
                    "FragmentPayload":payload_hexa,
                    "FragmentPayloadLength":payload_len,
                    "RCS":rcs_hexa,
                    "AllOne":all1,
                    "abort":abort,
                    "ack":ack,
                    "ack_req":ack_request,
                    "recever_abort_hexa":recever_abort,
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

            # We parse the IPv6 Packet
            parsed_pkt, residue, parsing_error = parser.parse(schc_pkt[1:], dir, layers=["IPv6", "UDP"])

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
            dev_iid = self.iid

            if dir == T_DIR_DW: #AA Downlink
                dev_iid = app_iid_l
                app_iid_l = self.iid

            dprint("chsm", chk_sum)

            for i, key in enumerate(keys):
                try:
                    if YANG_ID[key[0]][1] == "fid-ipv6-deviid":
                        dprint("iid", values[i][0], self.iid)
                        if values[i][0] == dev_iid:
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

    def generate_schc_msg(self, packet = None, hint = {"RuleIDValue": 101}, padding = None):
        # packet -> IPv6/UDP in bytes
        # hint -> JSON format

        t_dir = T_DIR_UP
        t_dir = hint["Direction"]
        rule_id = hint["RuleIDValue"]
        parser = Parser(self)

        json = {}
        schc_packet = bytearray()

        rule = self.rm.FindRuleFromRuleID (device = self.device_id, ruleID = rule_id )
        dprint("Rule", rule)
        # We parse the packet

        if packet != None and T_COMP in rule:

            comp = Compressor(self)
            parsed_packet, residue, parsing_error = parser.parse(packet, t_dir, layers=["IPv6", "UDP"])
            
            # We search for a rule that matches the packet:

            rule, self.device_id = self.rm.FindRuleFromPacket(parsed_packet, direction=t_dir)
            dprint("rule",rule)
            if rule == None:
                dprint("Rule does not match packet")
                return None, None

            ruleid_value = rule[T_RULEID]

            if ruleid_value == hint["RuleIDValue"]:
                schc_packet_comp = comp.compress(rule, parsed_packet, residue, t_dir)
                json = self.parse_schc_msg(schc_packet_comp._content)
                schc_packet = schc_packet_comp._content
            else:
                dprint("Rule in packet does not match hint")
                return None, None
            dprint (schc_packet)
        else:
        
            rule = self.rm.FindRuleFromRuleID(device=self.device_id, ruleID=rule_id)

            if T_FRAG in rule:
                if rule['Fragmentation']['FRMode'] == 'AckOnError':
                    if t_dir == T_DIR_DW: # Create Receiver Abort
                        receiver_abort = binascii.unhexlify("14ffff")
                        json = self.parse_schc_msg(schc_pkt = receiver_abort, dir = t_dir)
                        dprint("ACK ON ERROR - Receiver Abort")
                    return json, receiver_abort
                if rule['Fragmentation']['FRMode'] == 'AckAlways':
                    fragments, rcs, json = SCHCParser.fragment_ack_always(self, packet, hint['MTU'], rule_id, padding = padding)
                    schc_packet = fragments


        return  json, schc_packet

    def fragment_ack_always(self, packet, mtu, rule_id, padding = ""):

        # list where the final fragments in bytearray will be sotred and returned to generate_schc_message ()
        padding_comp = padding
        fragments = [None] * (math.ceil(len(packet) / mtu))
        packet_len = len(packet)
        
        dprint ('padding at compression', padding)
        dprint("type", type(packet))
        dprint("packet to be fragmented", packet, "packet len", len(packet), mtu)
        dprint('number of fragments', len(fragments))

        # We convert the packet in bits
        bytes_as_bits = ''.join(format(byte, '08b') for byte in packet)

        dprint('padding',padding)
        dprint ("padding_comp", padding_comp)
        if padding_comp != 0:
            len_diff = len(bytes_as_bits) - len(padding_comp)
            bytes_as_bits = bytes_as_bits[:len_diff]

        dprint ("len_bits", len(bytes_as_bits))

        # We create the headers TODO better
        wfcn = []
        dprint ("len(fragments)", len(fragments))
        if len(fragments) == 3:
            wfcn = ['00','10','01']
        else:
            wfcn = ['00','11']

        #wfcn = ['AA','BB','CC']

        # pas corresponds to the length of the fragments in bits minus the headers
        pas = mtu * 8 - 2

        dprint ("pas", pas)
        dprint ("bytes_as_bits", len(bytes_as_bits))

        bValues = [bytes_as_bits[i:i+pas] for i in range(0, len(bytes_as_bits), pas)]
        fragments =  [wfcn[i] + bValues[i] for i in range(0, len(bValues))]

        payload_bin = [bytes_as_bits[i:i+pas] for i in range(0, len(bytes_as_bits), pas)]

        dprint("payload_bin", len(payload_bin[0]), len(payload_bin[1]), payload_bin)

        # we put the information of fragments inside the variable fragments, we add padding to the last one if needed
        for idx, fragment in enumerate(fragments):
            bValues[idx] = [fragment[i:i+8] for i in range(0, len(fragment), 8)]
            if len(bValues[idx][-1]) != 8 : 
                padding = format(0, "0" + str(8 - len(bValues[idx][-1])) + "b") # padding_len
                bValues[idx][-1] = bValues[idx][-1] + padding
                fragments[-1] = fragments[-1] + padding

        dprint("len_last", len(fragments[-1]) / 8)
        

        # We create a variable including the total length of the packet plus the padding
        full_pkt = bytes_as_bits + padding

        # Add padding to padding if necessary for computing RCS
        padding_len = len(full_pkt) % 8

        if padding_len != 0 : 
            padding_a = format(0, "0" + str(padding_len) + "b") # padding_len
            full_pkt = bytes_as_bits + padding_a

        # Convert to hexa
        bValues_full = [full_pkt[i:i+8] for i in range(0, len(full_pkt), 8)]
        full_pkt_array = bytearray()
        for bValue in bValues_full:
                #print ("bValue",bValue)
                local_bytearray = int(bValue, 2).to_bytes((len(bValue) + 7) // 8, byteorder='big')
                full_pkt_array += local_bytearray

        rcs_pay = binascii.crc32(full_pkt_array)
        #rcs_pay_hexa = rcs_pay.to_bytes(4, 'big')

        rcs_pay_bits = format(rcs_pay, "032b")

        # We put the RCS after the header:

        fragments[-1] = fragments[-1][:2] + rcs_pay_bits + fragments[-1][2:]
        #print("last fragment", fragments[-1], len(fragments[-1]))

        # separate the packets into fragments:

        for idx, fragment in enumerate(fragments):
            bValues[idx] = [fragment[i:i+8] for i in range(0, len(fragment), 8)]

        fragments_hexa = []
        local_hexa = bytearray()
        for idx, bValues in enumerate(bValues):
            for bValue in bValues:
                local_bytearray = int(bValue, 2).to_bytes((len(bValue) + 7) // 8, byteorder='big')
                local_hexa += local_bytearray
            fragments_hexa.append(local_hexa)
            local_hexa = bytearray()

        for idx, _ in enumerate(fragments_hexa):
            dprint("len of frag = ", idx, len(fragments_hexa[idx]))

        # we pars the fragments
       
        rule_id_bytes = rule_id.to_bytes(1, byteorder='big')
        json = []
        for idx, frag in enumerate (fragments_hexa):
            json.append(self.parse_schc_msg(rule_id_bytes + frag, 
                                       dir = T_DIR_DW, 
                                       rcs_aa = rcs_pay, 
                                       payload_aa = payload_bin[idx]))
        return fragments_hexa, rcs_pay, json
        
    def generate_schc_comp(self, RuleID, dev_prefix, app_prefix):

        rule = self.rm.FindRuleFromRuleID(device = self.device_id, ruleID=RuleID)

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
                dprint("RuleID is a compression rule but args does not match with the rule")
                return None
        else:
            dprint("Not a compression RuleID")
            return None 

        return comp
