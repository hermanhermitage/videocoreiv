from idc import *
from idautils import *

sdata_seg = get_segm_by_name(".sdata")
if sdata_seg:
	bsVal = sdata_seg.startEA
else:
	bsVal = AskAddr(bsVal, "BS value for current code")

do_bs_stuff = AskYN(0,"Should code fix bs and pc references?")
if do_bs_stuff == -1:
	assert(0)
non_dry_strings = AskYN(0, "Should code convert suspected string to strings, or should it just print them?")

def find_bs_accesses():
	print "[+] Finding the bs accesses"
	# find all the pushes.

	# For each of the segments
	for seg_ea in Segments():
		# For each of the defined elements
		for head in Heads(seg_ea, SegEnd(seg_ea)):
			# If it's an instruction
			if head > 0xec50000 and isCode(GetFlags(head)):
				mnem = GetMnem(head)
				if(mnem == "add") and GetOpType(head,1) == o_reg and GetOpnd(head,1) == "bs" and GetOpType(head,2) == o_imm:
                                                OpOff(head, 2, 0)
						op2 = GetOpnd(head,2)
						intop2 = 0
						try:
							intop2 = int(op2[0:-1],16)
						except:
							# not a hex opcode
							continue
                                                print "[+] got: add reg,bs,%s @ 0x%x" % (op2,head)
                                                # change to ds offset
                                                add_dref(head,intop2+bsVal,dr_R)
                                                OpOff(head, 2, bsVal)
                                if  ( ((mnem.startswith("ld")) or (mnem == "lea") or (mnem.startswith("st"))) and GetOpType(head,1) == o_displ):
                                    firstOp = GetOpnd(head,1)
                                    displ = 0
                                    if firstOp.find("(bs)") != -1:
                                        displ = bsVal
                                    elif firstOp.find("(pc)") != -1:
                                        displ = head
                                    else:
                                        continue
                                    op1 = firstOp.split("(")[0]
                                    try:
                                        intop1 = int(op1[0:-1],16)
                                    except:
                                        continue
                                    print "[+] got:",mnem," reg,%s @ 0x%x" %(firstOp,head)
				    if not mnem.startswith("st"):
					    add_dref(head,intop1+displ,dr_R)
				    else:
					    add_dref(head,intop1+displ,dr_W)
                                    OpOff(head, 1, displ)
                                    


if do_bs_stuff:
	find_bs_accesses()

				    
def isStringLike(start_addr, max_len):
	se = []
	for i in range(max_len):
		ch = chr(Byte(start_addr+i))
		if ch == "\0":
			return (i,"".join(se))
		if ch not in string.printable or RfirstB0(start_addr+i) != 0xFFFFFFFF:
			return (False,"")
		se.append(ch)
	return (False,"")

def isBadStr(s):
	return s == "`Z" or s == "hZ" or s == " `0\rZ" or s == "p`0\rZ" or s == "\x70\x60\x20\x0D" or s =="@`Z" or s == "\x73\x60" or s == "P@@n" or s == " `Z" or s == "P\x0d" or s =="S`" or s == "c`" or s == " `" or s == "PPPP" or s == "l@P" or s == "\x0C`P" or s == "<KP" or s == "@KP" or s == "\x0C\x0B" or s == "@#" or s == "`!" or s =="D'" or s == "\x3C\x09" or s == "`\x0b" or s =="` " or s == "P5" or  s == " @Z" or s == "33" or s == "3333ffff" or s == "UUUU" or s == "p`P\x0DZ" or s == "hy" or s == "3l" or s == ",f" or s == "p`" or s == "RH" or s == "JD" or s == "t@" or s == "q9" or s == ";6" or s == "UO" or s == "/3" or s == "g&" or s == ">$" or s == "6\"" or s == " @Z" or s == "C`" or s == " y" or s == "Zr" or s == "7`" or s == "AX" or s == "|]" or s == "QS" or s == "mL" or s == "BJ" or s == "'H" or s == "/B" or s == "N@" or s == "{>" or s == "P9" or s == "90" or s == ";," or s == "l'" or s == "N&" or s == ")$" or s == "UO" or s == "phZ" or s == "NKa"

blackList = set([0xED6F692,0xED6F68E,0xED6F3B6,0xED20944,0xED208E2,0xEC9ADD6])
def isBadAddr(ea):
	if ea in blackList:
		return True
	if ea >= 0x80e2338 and ea <= 0x80e2737:
		return True
	return False

def find_code_strs():
	print "[+] Finding the strings in the file"
	# find all the pushes.
	# For each of the segments
	for seg_ea in Segments():
		# For each of the defined elements
		for head in Heads(seg_ea, SegEnd(seg_ea)):
			# If it's an instruction
			if (head &0xFFFF) == 0:
				print "[+] At addr "+hex(head)
			if isCode(GetFlags(head)):
				data = (Byte(head) << 8) | Byte(head+1)
				funcEnd =  ((data & 0x80FF) == 0x0003) or data == 0x5A00
				funcEnd = funcEnd or ((data & 0x80FF) == 0x001F)
				funcEnd = funcEnd or ((data & 0xE0FF) == 0x4000)
				funcEnd = funcEnd or ((data & 0xFF) == 0x8E)
				funcEnd = funcEnd or ((data & 0x80FF) == 0x009E)
				if data &0x80:
					head = head + 2
				if data == 0x0000 or data == 0x0100 or funcEnd :
					head = head + 2
					if (head & 0x3):
						continue
					if  (head in blackList):
						print "Skipping blacklisted STR at",hex(head)
						continue
					slen,s = isStringLike(head, MAX_STR_LEN)
					while slen > 1:
						if s.find("p`") >= 0:
							print "Suspect:",[hex(ord(x)) for x in s]
						if isBadStr(s):
							print "Skipping str",s,"at",hex(head)
							break
						if isBadAddr(head):
							print "Bad addr",head,"skipping string",s
							break
						if not isASCII(GetFlags(head)):
							if non_dry_strings:
								MakeUnknown(head,slen,DOUNK_EXPAND)
								MakeStr(head,BADADDR)
							print "Made string "+hex(head)+": "+s
						head = head+slen+1
						while Byte(head) == 0:
							head += 1
						if head &0x3:
							break
						slen,s = isStringLike(head, MAX_STR_LEN)
find_code_strs()
