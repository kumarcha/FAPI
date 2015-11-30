#!/usr/bin/python
import sys
from re import search,match,I
from Functions_2 import *
if len(sys.argv)==2:
	FILE_NAME=sys.argv[1]
else:
	sys.exit('Please provide proper cmd line args!')
Frame=None
Msg_Id=None
'''List of Message Type and corresponding msg_id 
	'0x80' 	:	'DL_CONFIG_REQUEST',
	'0x81' 	:	'UL_CONFIG_REQUEST',
	'0x82'	:	'SUBFRAME_INDICATION',
	'0x83'	:	'HI_DCI0_REQUEST',
	'0x84'	:	'TX_REQUEST',
	'0x85'	:	'HARQ_INDICATION',
	'0x86'	:	'CRC_INDICATION',
	'0x87'	:	'RX_ULSCH_INDICATION',
	'0x88'	:	'RACH_INDICATION',
	'0x89'	:	'SRS_INDICATION',
	'0x8a'	:	'RX_SR_INDICATION',
	'0x8b'	:	'RX_CQI_INDICATION'
'''
with open(FILE_NAME,'r') as FH:
	for line in FH:
		if search("^\s*Frame\s*number\s*:\s*\d+",line,I):
			Frame=int(line.split(":")[1].strip())
		elif "Msg Id:" in line:
			R=search("^\s*msg\s*id\s*:\s*(0x[a-fA-F0-9]+)\s*\(\d+\)",line,I)
			Msg_Id=R.group(1)
			if Msg_Id=='0x87':
				Message=RX_ULSCH_IND(FH,Frame)
				print Message
		
	
