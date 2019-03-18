import idaapi, idc, idautils

#make sure IDA.cfg allows _ in function names (It does by default)
#don't forget to double \'s 
FILE="<CompanionFileHere>"

def do_rename(line):
	presplitline = line.split("|") #use : for joker, | for jtool2 (joker has been deprecated per the forums
	address = presplitline[0]
	newName = presplitline[1].replace("\r", "").replace("\n", "")
	address = int(address,16) #16 = base
	#print "%s %s" % (address,newName)
	idc.MakeName(address, newName)
	

if __name__ == "__main__":
	f = open(FILE, "r")
	for line in f:
		do_rename(line)
	f.close()
	print "Done!\n"
