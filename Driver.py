#!/usr/bin/python
from os import path,system
try:
	import xlsxwriter,sys #import xlsxwriter
except ImportError:
	sys.exit('Please install Python xlsxwriter module!!\n') #exception at importing xlsxwriter
from Functions import * #Import all sub routines from File Functions
from re import search,match,I,findall # import search,match and Ignore Case from Regular Expression(Module name :re)	
File_pcap=False
if len(sys.argv) ==3:
	LOG_FILE_NAME=sys.argv[1]		#provide log file using command line argument
	SYS_BW=sys.argv[2]
	if SYS_BW.isdigit():
		SYS_BW=int(SYS_BW)
	elif SYS_BW.isalpha():
		sys.exit('System Bandwidth Should have some numeric value!!')
	elif SYS_BW.isalnum():
		SYS_BW=findall('\d+|[a-zA-Z]+',SYS_BW)[0]
		if SYS_BW.isalpha():
			sys.exit('Please give numeric value first in System Bandwidth')
		elif SYS_BW.isdigit():
			SYS_BW=int(SYS_BW)
	if int(SYS_BW) not in [1.4,3,5,10,20]:
		sys.exit('Invalid System Bandwidth!! LTE Supoorts [1.4,3,5,6,15,20] MHz Only.')
	if search("\.pcap",LOG_FILE_NAME,I):
		LOG_FILE_NAME=pcap2textConvert(LOG_FILE_NAME)	
		EXCEL_FILE_NAME=LOG_FILE_NAME.split(".")[0]+".xlsx"	
		File_pcap=True		#Generate Excel file with same name as log file
	elif search("\.txt|\.log",LOG_FILE_NAME,I):
		EXCEL_FILE_NAME=LOG_FILE_NAME.split(".")[0]+".xlsx"			#Generate Excel file with same name as log file
	else:
		#EXCEL_FILE_NAME=LOG_FILE_NAME+".xlsx"			#Generate Excel file with same name as log file
		sys.exit('File type is not supported.Please rename it with supported file extension(pcap for capture file or txt/log for simple text file)')
else:
	sys.exit('Only one command line argument is required!!\nPlease give Log file name as command line argument.')
	
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
generateREADME()
global row;
workbook=None
row=2;SIB_Comment=0;MIB_Comment=0
Max_row=65535 #Max number of row in one worksheet
worksheet_count=0 #counter for worksheet
Frame=0;
count=0
UL_Q=[] #UL Q maintaining Queue of Lenght 4 for message UL_Config. This will be used to find RNTI,Channel Type for HI,CQI,SR messages
global CRC_Mesage
CRC_Message={}
try:
	# Open Log File in Some file Handler
	with open(LOG_FILE_NAME,"r") as LOG_FH:
		workbook = xlsxwriter.Workbook(EXCEL_FILE_NAME)  #creating a work book and inside that creating a sheet in Excel
		worksheet =workbook.add_worksheet('Analysis_'+str(worksheet_count))
		format=workbook.add_format();format.set_bg_color('#33FF33');format.set_align('center');format.set_border() #format for 1st line Green in Color center align
		format1=workbook.add_format();format1.set_align('center');
		createHeaderToExcel(worksheet,format) #Writing 1st line i.e Header Meassage in Excel
		worksheet.freeze_panes(2, 0,) #Freeze first row
		for line in LOG_FH:
			if row>Max_row:
				worksheet_count+=1
				worksheet=workbook.add_worksheet('Analysis_'+str(worksheet_count))
				worksheet.activate()
				createHeaderToExcel(worksheet,format)
				worksheet.freeze_panes(2, 0,)
				#global SIB_Comment;global MIB_Comment;
				row=2;SIB_Comment=0;MIB_Comment=0
			if search("Frame Number:",line,I):
				Frame=int(line.split(":")[1].strip())
			elif search("Msg Id:",line,I):
				Msg_id=line.split(":")[1].split()[0]
				if Msg_id=="0x80" :
					row=DL_CONFIG_REQ(LOG_FH,Frame,worksheet,row,format1,SYS_BW)
				elif Msg_id=="0x81":
					T=UL_CONFIG_REQ(LOG_FH)
					if len(UL_Q) <4:
						UL_Q.insert(0,T.copy())
						del T
					else:
						UL_Q.pop()
						UL_Q.insert(0,T.copy())
						del T
				elif Msg_id =="0x82":
					SUBFRAME_IND()
				elif Msg_id=="0x83":
					row=HI_DCI0_REQ(LOG_FH,Frame,worksheet,row,format1,UL_Q)
				elif Msg_id=="0x84":
					row,SIB_Comment,MIB_Comment=TX_REQ(LOG_FH,Frame,worksheet,row,format1,SIB_Comment,MIB_Comment,SYS_BW)
				elif Msg_id=="0x85":
					row=HARQ_IND(LOG_FH,Frame,worksheet,row,format1,UL_Q)
				elif Msg_id=="0x86":
					CRC_Message=CRC_IND(LOG_FH,Frame,worksheet,row,format1)
				elif Msg_id=="0x87":
					row=RX_ULSCH_IND(LOG_FH,Frame,worksheet,row,format1,CRC_Message); 
				elif Msg_id=="0x88":
					row=RACH_IND(LOG_FH,Frame,worksheet,row,format1)
				elif Msg_id=="0x89":
					row=SRS_IND(LOG_FH,Frame,worksheet,row,format1)
					count+=1
				elif Msg_id=="0x8a":
					row=RX_SR_IND(LOG_FH,Frame,worksheet,row,format1,UL_Q)
				elif Msg_id=="0x8b":
					row=RX_CQI_IND(LOG_FH,Frame,worksheet,row,format1,UL_Q)
				else:
					continue
		#print UL_Q
except IOError:
	sys.exit("Log File Not found!!")    
if workbook!= None:
	try:
		workbook.close()
	except :
		# Handle your exception here.
		sys.exit("Colse the file if opened or Couldn't create xlsx file")
else:
	del workbook
if File_pcap:
	if search("linux",sys.platform(),I):
		command="rm -rf "+LOG_FILE_NAME
	elif search("win32",sys.platform(),I):
		command="del \Q "+LOG_FILE_NAME
	system(command)

	
