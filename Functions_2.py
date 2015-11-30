#!/usr/bin/python
from re import search,match,I
def RX_ULSCH_IND(FH,Frame):
	Message={}
	for line in FH:
		if "Sf:" in line:
			R=search("^\s*.*sf:\s*(\d)",line,I)
			Message.update(SF=int(R.group(1)))
		elif "Sfn:" in line:
			R=search("^\s*.*sfn:\s*(\d+)",line,I)
			Message.update(SFN=int(R.group(1)))
		elif search("^\s*Frame\s*\d+\s*:",line,I):
			break
		elif search("^\s*Rnti\s*:\s*0x[A-Fa-f0-9]+\s*\(\d+\)",line,I):
			Message.update(RNTI=int(line.split('(')[1].split(')')[0]))
		elif search("^\s*c1:\s*\w+\s*\(\d+\)",line,I):
			rrc_msg=line.split(":")[1].split()[0].lower()
			if rrc_msg=="rrcconnectionrequest":
				Message.update(RRC_Message=rrc_msg)
				while True:
					temp_line=FH.next()
					if "establishmentCause:" in temp_line:
						R=search("^\s*establishmentcause\s*:\s*(\w+-?\w+)\s*\(\d+\)",temp_line,I)
						Message.update(Cause=R.group(1))
					elif search("^\s*$",temp_line,I):
						break
	if "RRC_Message" in Message:
		 return Message 

