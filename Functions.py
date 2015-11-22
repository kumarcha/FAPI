#!/usr/bin/python
###########################################################################
# 	File Name 		:	Function.py
# 	Author 			:	Chandan Kumar(chandan.kumar@votarytech.com)
# 	Discription 	:	This file have function definition of each Message_type
#	Copyright		:	VotaryTech Solution 
###########################################################################

# Importing required functions from its respective module
from re import search,match,I,sub
from os import path,system,_exit
from math import log,ceil
#Message Header 1st Line of Excel Sheet
Message_Header=['PACKET_NUMBER','Msg_Type','SFN','SF','RNTI','RNTI_TYPE','RRC_Message','NAS_Message','DL_PHY_CH','UL_PHY_CH','CFI','DL_DCI',
'DL_PDCCH_INFO','UL_DCI','UL_PDCCH_INFO','RACH_CONTENT','RAR_CONTENT','PHICH_INFO','RI','CQI_PMI_INFO','DL_HARQ_TB_1','DL_HARQ_TB_2','SRS','BSR','PHR','CRC']
nRB={1.4:6,3:15,5:25,10:50,20:100}
P_Value=0
DL_BW=0
###########################################################################
# 	Function Name 	:	DL_CONFIG_REQ
# 	Author					:	Chandan Kumar(chandan.kumar@votarytech.com) 
#		Input 					:	FH -> FileHandler
#											Frame -> Wireshark Frame Number
#											worksheet -> Current worksheet
#											row -> Current row in worksheet
#											format1 -> Format for writing data in a cell 
#	Return Value			:	Row number 
#	Description				:	This function process only DCI PDU in DL_Config.request(Msg.Id=0x80) Message.
#											For each PDU data has been written in Excel Sheet after which next row number has been returned to Driver.py
###########################################################################
def DL_CONFIG_REQ(FH,Frame,worksheet,row,format1,SYS_BW):
	global P_Value,DL_BW
	Message={} #This DS will store all releavent information within one Frame
	Message['PACKET_NUMBER']=Frame
	for line in FH:
		count=-1;N_DCI=0; # N_DCI is the number of DCI Present in Frame and Count is used as index for different PDUs
		DL_BW=nRB[SYS_BW]
		flag=0;Avail_BW=DL_BW
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("CFI:",line):
			Message['CFI']=int(line.split("(")[1].split(")")[0].rstrip())
		elif search("Num of DCI:",line):
			Message['N_DCI']=int(line.split("(")[1].split(")")[0].rstrip())
			N_DCI=Message['N_DCI'] 
		if 'N_DCI' in Message and N_DCI>0:
			Message['PDUs']={}
			flag=0
			Message['DL_PHY_CH']="PDCCH"
			while N_DCI>=0:
				temp_line=FH.next()
				if search("DL CONFIG PDU INFO",temp_line,I):
					flag=1
				elif search("DCI DL PDU INFO",temp_line) and flag==1:
					count=count+1
					Message['PDUs']['DCI'+str(count)]={} # Creating New Field for each DCI Pdu
					N_DCI=N_DCI-1;flag=2
					Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO']="" # Information About DL_PDCCH
				elif search("DciFormat",temp_line) and flag==2:
					Message['PDUs']['DCI'+str(count)]['DL_DCI']=temp_line.split(":")[1].split("_")[-1].split()[0]
				elif search("rnti:",temp_line) and flag==2:
					Message['PDUs']['DCI'+str(count)]['RNTI']=temp_line.split(":")[1].split('(')[1].split(')')[0]
					rnti=Message['PDUs']['DCI'+str(count)]['RNTI']
				elif search("MCS\s+\d+:",temp_line,I)and flag==2:
					key=temp_line.split(":")[0].strip();value=temp_line.split(":")[1].split("(")[1].split(")")[0]
					Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO']=key+":"+value+";"+Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO'].rstrip() # Concating Strings
				elif search("new Data Indicator\s\d+:",temp_line,I) and flag==2:
					key=temp_line.split(":")[0].strip().split()[-1];value=temp_line.split(":")[1].split("(")[1].split(")")[0]
					Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO']="NDI_"+key+":"+value+";"+Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO'].rstrip()
				elif search("^\s+rb+\s+coding\s*:\s+0x.*\s+\(\d+\)",temp_line,I) and flag==2:
					key=temp_line.strip().split(":")[0];value=bin(int(temp_line.split(":")[1].split()[1].split('(')[1].split(')')[0])).split('b')[1]
					key1="NoOfRBs";value1=value.count('1')
					if P_Value==0:
						P_Value=getP_Value(DL_BW)
					NoOfRbs=int(get_NoofRbs(value1,Message['PDUs']['DCI'+str(count)]['DL_DCI']))
					if NoOfRbs>Avail_BW:
						NoOfRbs=Avail_BW
					else:
						Avail_BW=Avail_BW-NoOfRbs
					Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO']=key+":"+value+"(NoOfRBs:"+str(NoOfRbs)+");"+Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO'].rstrip()
				elif search("harq Process Num:",temp_line,I) and flag==2:
					key=temp_line.split(":")[0].strip();value=temp_line.split(":")[1].split("(")[1].split(")")[0]
					Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO']="HarqPID"+":"+value+";"+Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO'].rstrip()
				elif search("redundancy Version\s\d+:",temp_line,I) and flag==2:
					key=temp_line.split(":")[0].strip().split()[-1];value=temp_line.split(":")[1].split("(")[1].split(")")[0]
					Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO']="RV"+key+":"+value+";"+Message['PDUs']['DCI'+str(count)]['DL_PDCCH_INFO'].rstrip()
				elif search("rnti Type:",temp_line) and flag==2:
					key=temp_line.split(":")[0].strip();
					if rnti=='65535':
						value='SI_RNTI'
					elif rnti=='65534':
						value='P_RNTI'
					else:
						#value='_'.join(temp_line.split(":")[1].split()[0].split("_")[1:])
						value='RA_RNTI'
					Message['PDUs']['DCI'+str(count)]['_'.join(key.upper().split())]=value
				elif search("^\s*$",temp_line):
					break # If New Line is there then End of Frame
				else:
					continue
	Message['Msg_Type']="DL_CONFIG_REQUEST"
	N_DCI=Message['N_DCI']
	Temp_Message={} # DS for each PDU; We will populate Temp_Message with relavent content for each row in Excel
	for key,value in Message.items():
		if key=="PDUs" or key =="N_DCI":
			continue # Skip copy PDUs here will do later. 
		else:
			Temp_Message[key]=value #Copy only common info from Message
	for no in range(N_DCI):
		for key,value in Message['PDUs']['DCI'+str(no)].items():
			Temp_Message[key]=value # Now Copy all values per PDU 
		writeToExcel(worksheet,row,format1,Temp_Message) # Write the Temp_Message DS to excel in single row
		row=row+1 # Increament Row for next Line in Excel
	del(Message,Temp_Message,N_DCI,Frame,flag,count) #Delete all Temporary Message after Writing data on Excel
	return row #return the Row number to Driver file 
###########################################################################
#	Function Name	:	get_NoofRbs
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	Bits -> number of ON(1) bits in RB Coding
#					DCi_Format -> DCI_FORMAT which is used in RB calculation
#	Return Value	:	No of RBs
#	Description		: 	Depending Upon Resource allocation type and DCI format no of RB is calculated.
#					Please refer TS 36.213 for more detail.
###########################################################################
def get_NoofRbs(Bits,Dci_Format):
	if match("^1[ABCD]",Dci_Format):
		return ceil(log((DL_BW*(DL_BW+1)/2),2))
	elif match("^[12]$|2A",Dci_Format):
		return ceil(Bits*P_Value)
		
###########################################################################
#	Function Name	:	UL_CONFIG_REQ
#	Author			:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	FH -> File Handler
#	Return Value	:	A Dictionary containing all relevent information of UL_Config Message
#	Description		:	This Function frames a dictionary for different PDU(ie. SR,CQI,HARQ,ULSCH and combination of these) with thier relevant Information.
#						This message dictionary is useful in finding the Channel Type(for CQI,SR and HARQ Indication) and RNTI value(FOR HI PDU in HI_DCI0)
#						The Message has been returned to Driver.py which is stored in UL_Q buffer.
###########################################################################						
def UL_CONFIG_REQ(FH):
	#This Function is used to Form Message Data Structure for UL Config. And this Message Data Structure will be returnd to Driver 
	# and there it will be maintain as Queue for geting information for HI,CQI and SR 
	Message={}
	CQI_count=HARQ_count=ULSCH_count=SR_count=-1 # Index for each PDU type 
	for line in FH:
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line,I):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of PDU:",line,I):
			N_PDU=int(line.split("(")[1].split(")")[0])
			if N_PDU>0:
				Message['N_PDU']=N_PDU
		if 'N_PDU' in Message and N_PDU>0:
			pdu_type="";No=0;
			Message['HARQ']={};Message['ULSCH']={};Message['CQI']={};Message['SR']={}
			while N_PDU>=0:
				temp_line=FH.next()
				if search("UL PDU CONFIGURATION INFO",temp_line,I):
					flag=0;ulconfigPdu="";N_PDU=N_PDU-1;
				elif search("ULConfigPduType",temp_line,I):
					ulconfigPdu=temp_line.split(":")[1].split()[0].rstrip()
				elif search("HARQ PDU Info",temp_line,I):
					pdu_type="HARQ";flag=1 #seting Pdu Type as HARQ PDU
					HARQ_count=HARQ_count+1
					No=HARQ_count
					Message[pdu_type][pdu_type+str(No)]={} # create new DS for pdu type
					Message[pdu_type][pdu_type+str(No)]['ULConfigPduType']=ulconfigPdu
				elif search("CQI PDU Info",temp_line,I):
					pdu_type="CQI";flag=1 #seting Pdu Type as CQI PDU
					CQI_count=CQI_count+1
					No=CQI_count
					Message[pdu_type][pdu_type+str(No)]={}
					Message[pdu_type][pdu_type+str(No)]['ULConfigPduType']=ulconfigPdu
				elif search("SR PDU INFO",temp_line,I):
					pdu_type="SR";flag=1 #seting Pdu Type as SR PDU
					SR_count=SR_count+1
					No=SR_count
					#print "SR PDU INFO",No
					Message[pdu_type][pdu_type+str(No)]={}
					Message[pdu_type][pdu_type+str(No)]['ULConfigPduType']=ulconfigPdu
				elif search("ULSCH PDU INFO",temp_line,I):
					pdu_type="ULSCH";flag=1 #seting Pdu Type as ULSCH PDU
					ULSCH_count=ULSCH_count+1
					No=ULSCH_count
					Message[pdu_type][pdu_type+str(No)]={};
					Message[pdu_type][pdu_type+str(No)]['ULConfigPduType']=ulconfigPdu
				elif search("Rnti:",temp_line,I) and flag==1:
					value=temp_line.split(":")[1].split("(")[1].split(")")[0].rstrip()
					Message[pdu_type][pdu_type+str(No)]['RNTI']=value;
				elif search("RB Start:",temp_line,I) and flag==1:
					key=temp_line.split(":")[0].strip();value=temp_line.split(":")[1].split("(")[1].split(")")[0] #Take RB Start
					Message[pdu_type][pdu_type+str(No)][key]=value;
				elif search("^\s*$",temp_line):
					break
				else:
					continue
	return (Message)
###########################################################################
#	Function Name	:	SUBFRAME_IND
#	This Function is not yet implememnted 
###########################################################################
def SUBFRAME_IND():
	pass
###########################################################################
#	Function Name	:	HI_DCI0_REQ
#	Author			:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	FH -> FileHandler
#					Frame -> Wireshark Frame Number
#					worksheet -> Current worksheet
#					row -> Current row in worksheet
#					format1 -> Format for writing data in a cell 
#					UL_Q -> BUffer Queue of lenght 4 SF
#	Return Value	:	Row number 
#	Description		:	This funtion collects all information of HI_DCI0 message.
#						For HI PDU the UL_Q buffer has been used to find its RNTI value(4 SF back checking RB Start in UL_Q) 
#						For each PDU data has been written in Excel Sheet after which next row number has been returned to Driver.py
###########################################################################
def HI_DCI0_REQ(FH,Frame,worksheet,row,format1,UL_Q):
	#This function to Process 
	Message={};N_DCI=N_HI=No=0;DCI_count=HI_count=-1;
	Message['PACKET_NUMBER']=Frame
	for line in FH:
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line,I):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of DCI:",line,I):
			Message['N_DCI']=int(line.split("(")[1].split(")")[0])
			N_DCI=Message['N_DCI']
		elif search("Num of HI:",line,I):
			Message['N_HI']=int(line.split("(")[1].split(")")[0])
			N_HI=Message['N_HI']
		if N_DCI>0 or N_HI>0:
			Message['HI']={};pdu_type="";Message['DCI']={}
			while N_HI>=0 or N_DCI>=0:
				temp_line=FH.next()
				if search("DCI PDU INFO",temp_line,I):
					pdu_type="DCI";DCI_count=DCI_count+1
					No=DCI_count;N_DCI=N_DCI-1;rb=0
					Message[pdu_type][pdu_type+str(No)]={}
					Message[pdu_type][pdu_type+str(No)]['UL_PDCCH_INFO']=""
					Message[pdu_type][pdu_type+str(No)]['DL_PHY_CH']="PDCCH"
				elif search("HI PDU INFO",temp_line,I):
					pdu_type="HI";HI_count=HI_count+1
					No=HI_count;N_HI=N_HI-1;rb=1
					Message[pdu_type][pdu_type+str(No)]={}
					Message[pdu_type][pdu_type+str(No)]['PHICH_INFO']=""
				elif search("hi pdu Size:",temp_line,I):
					#key="HI_PDU_SIZE:";value=temp_line.split("(")[1].split(")")[0]
					#Message[pdu_type][pdu_type+str(No)]['PHICH_INFO']+=key+value+";"
					pass
				elif search("RB Start:",temp_line,I)and rb==1:
					#key="RB Start:";value=temp_line.split("(")[1].split(")")[0] # Take RB Start
					#Message[pdu_type][pdu_type+str(No)]['PHICH_INFO']+=key+value+";"
					rb_start=temp_line.split("(")[1].split(")")[0]
				elif search("HI Value:",temp_line,I):
					key="HI Value:";value=temp_line.split(":")[1].split()[0]
					Message[pdu_type][pdu_type+str(No)]['PHICH_INFO']+=value+";" #Take HI Value
				elif search("I PHICH:",temp_line,I):
					Message[pdu_type][pdu_type+str(No)]['DL_PHY_CH']="PHICH"
				elif search("ul DCI Format:",temp_line,I):
					Message[pdu_type][pdu_type+str(No)]['UL_DCI']="DCI"+temp_line.split("(")[1].split(")")[0]
				elif search("rnti:",temp_line,I):
					Message[pdu_type][pdu_type+str(No)]['RNTI']=temp_line.split("(")[1].split(")")[0]
				elif search("Agg Level:",temp_line,I):
					key="Agg Level:";value=temp_line.split(":")[1].split()[0].split('_')[-1]
					Message[pdu_type][pdu_type+str(No)]['UL_PDCCH_INFO']+=key+value+";"
				elif search("RB Start:",temp_line,I)and rb==0:
					key="RB Start:";value=temp_line.split("(")[1].split(")")[0]
					Message[pdu_type][pdu_type+str(No)]['UL_PDCCH_INFO']+=key+value+";"
				elif search("num Of RB:",temp_line,I):
					key="num Of RB:";value=temp_line.split("(")[1].split(")")[0]
					Message[pdu_type][pdu_type+str(No)]['UL_PDCCH_INFO']+=key+value+";"
				elif search("MCS:",temp_line,I):
					key="MCS:";value=temp_line.split("(")[1].split(")")[0]
					Message[pdu_type][pdu_type+str(No)]['UL_PDCCH_INFO']+=key+value+";"
				elif search("new Data Indication:",temp_line,I):
					key="NDI:";value=temp_line.split("(")[1].split(")")[0]
					Message[pdu_type][pdu_type+str(No)]['UL_PDCCH_INFO']+=key+value+";"
				elif search("^\s*cqi\s*request\s*:\s*\w+\s*\(0x\d+\)\s*$",temp_line,I):
					key="APERIODIC_CQI:";value=temp_line.split('CQI_')[1].split()[0];
					Message[pdu_type][pdu_type+str(No)]['UL_PDCCH_INFO']+=key+value+";"
				elif search("^\s*$",temp_line):
					break
				else:
					continue
	Message['Msg_Type']="HI_DCI0_REQUEST"
	N_DCI=len(Message['DCI']);N_HI=len(Message['HI'])
	Temp_Message={}
	p_type=""
	for i in range(2):
		if i==0:
			p_type="DCI";count=N_DCI;
		elif i==1:
			p_type="HI";count=N_HI;
		for key,value in Message.items():
			if key in ['DCI','HI','N_DCI','N_HI']:
				continue
			else:
				Temp_Message[key]=value
		for no in range(count):
			for key,value in Message[p_type][p_type+str(no)].items():
				Temp_Message[key]=value
			if i==1:
				sfn,sf=get_sfn_sf(Message['SFN'],Message['SF'])
#				rb_start=""
				#rb_start=int(Temp_Message['PHICH_INFO'].split("RB Start")[1].split(";")[0].split(":")[1])
				RNTI=get_data_from_UL_Q(sfn,sf,"ULSCH",None,1,None,rb_start,UL_Q)
				Temp_Message['RNTI']=RNTI
			if Temp_Message['RNTI'] not in ['',None]:
				Temp_Message['RNTI_TYPE']='C_RNTI'
			writeToExcel(worksheet,row,format1,Temp_Message)
			row=row+1
		Temp_Message.clear()
	del(Message,Temp_Message,N_HI,N_DCI,p_type,DCI_count,HI_count,no,count,Frame)
	return row
###########################################################################
#	Function Name	:	HARQ_IND
#	Author			:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	FH -> FileHandler
#						Frame -> Wireshark Frame Number
#						worksheet -> Current worksheet
#						row -> Current row in worksheet
#						format1 -> Format for writing data in a cell 
#						UL_Q -> BUffer Queue of lenght 4 SF
#	Return Value	:	Row number 
#	Description		:	This funtion collects all information of Harq.Indication message.
#						For getting channel type UL_Q buffer has been used to find its Channel Type(Same SF checking RNTI and its corresponding Channel Type in UL_Q) 
#						For each PDU data has been written in Excel Sheet after which next row number has been returned to Driver.py
###########################################################################
		
def HARQ_IND(FH,Frame,worksheet,row,format1,UL_Q):
	Message={};N_HARQ=0;
	Message['PACKET_NUMBER']=Frame
	for line in FH:
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("numOfHarq:",line,I):
			Message['N_HARQ']=int(line.split("(")[1].split(")")[0])
			N_HARQ=Message['N_HARQ']
		if N_HARQ>0:
			Message['PDUs']={};count=-1
			while N_HARQ>=0:
				temp_line=FH.next()
				if search("HARQ PDU Indication",temp_line,I):
					count=count+1
					Message['PDUs']['HARQ'+str(count)]={}
					N_HARQ=N_HARQ-1
				elif search("RNTI:",temp_line,I):
					Message['PDUs']['HARQ'+str(count)]['RNTI']=temp_line.split('(')[1].split(')')[0]
					Message['PDUs']['HARQ'+str(count)]['RNTI_TYPE']="C_RNTI"
				elif search("HARQ TB 1:",temp_line,I):
					Message['PDUs']['HARQ'+str(count)]['DL_HARQ_TB_1']=temp_line.split(":")[1].split()[0]
				elif search("HARQ TB 2:",temp_line,I):
					#Message['PDUs']['HARQ'+str(count)]['DL_HARQ_TB_2']=temp_line.split(":")[1].split()[0]
					pass
				elif search("^\s*$",temp_line,I):
					break
				else:
					continue
	Message['Msg_Type']="HARQ_INDICATION"
	N_HARQ=Message['N_HARQ']
	Temp_Message={}
	for key,value in Message.items():
		if key in ['PDUs','N_HARQ']:
			continue
		else:
			Temp_Message[key]=value
	for no in range(N_HARQ):
		for key,value in Message['PDUs']['HARQ'+str(no)].items():
			Temp_Message[key]=value
		Temp_Message['UL_PHY_CH']=get_data_from_UL_Q(Message['SFN'],Message['SF'],"HARQ",Temp_Message['RNTI'],None,1,None,UL_Q)
		writeToExcel(worksheet,row,format1,Temp_Message)
		row=row+1
	del(Message,Temp_Message,N_HARQ,no,count,Frame)
	return row
###########################################################################
#	Function Name	:	CRC_IND
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Inputs		:	FH -> File Handler
#					Frame -> Wireshark Frame Number
#					worksheet -> Current worksheet
#					row -> Current row in worksheet
#					format1 -> Format for writing data in a cell 
#	Return Value	:	A Dictionary to Driver.py
#	Description		:	This function collects all required information  in CRC.Indication message and stored in a dictionary
#					This dictionary is returned to Driver.py which is then passed to RX_ULSCH.Indication Message.			
###########################################################################

def CRC_IND(FH,Frame,worksheet,row,format1):
	Message={}
	Message['PACKET_NUMBER']=Frame
	for line in FH:
		N_CRC=0
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of CRC:",line,I):
			Message['N_CRC']=int(line.split("(")[1].split(")")[0])
			N_CRC=Message['N_CRC']
		if N_CRC>0:
			Message['PDUs']={}
			count=-1
			while N_CRC>=0:
				temp_line=FH.next()
				if search("CRC PDU Indication",temp_line,I):
					count=count+1
					Message['PDUs']['CRC'+str(count)]={}
					N_CRC=N_CRC-1
				elif search("RNTI:",temp_line,I):
					Message['PDUs']['CRC'+str(count)]['RNTI']=temp_line.split("(")[1].split(")")[0]
					Message['PDUs']['CRC'+str(count)]['RNTI_TYPE']="C_RNTI"
				elif search("CRC Flag:",temp_line,I):
					Message['PDUs']['CRC'+str(count)]['CRC']=temp_line.split(":")[1].strip().split()[0]
				elif match("^\s*$",temp_line):
					break
				else :
					continue
	#Message['Msg_Type']="CRC_INDICATION"
	'''
	N_CRC=Message['N_CRC']
	print Message
	Temp_Message={}
	for key,value in Message.items():
		if key in ['PDUs','N_CRC']:
			continue
		else:
			Temp_Message[key]=value
	for no in range(N_CRC):
		for key,value in Message['PDUs']['CRC'+str(no)].items():
			Temp_Message[key]=value
		writeToExcel(worksheet,row,format1,Temp_Message)
		row=row+1
	del(Message,Temp_Message,N_CRC,no,count,Frame)
	'''
	return Message
###########################################################################
#	FUnction Name	:	RX_ULSCH_IND
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	FH -> FileHandler
#					Frame -> Wireshark Frame Number
#					worksheet -> Current worksheet
#					row -> Current row in worksheet
#					format1 -> Format for writing data in a cell 
#	Return Value	:	Row Number 
#	Description		:	This funtion collects all information of RX_ULSCH_IND message.
#					For each PDU data has been written in Excel Sheet after which next row number has been returned to Driver.py
###########################################################################
def RX_ULSCH_IND(FH,Frame_No,worksheet,row,format1,CRC_Message): 
	Message={};N_PDU=0;Message['Msg_Type']="RX_ULSCH_IND";
	Message['PACKET_NUMBER']=Frame_No
	for line in FH:
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of PDU:",line,I):
			Message['N_PDU']=int(line.split("(")[1].split(")")[0].rstrip())
			N_PDU=Message['N_PDU']
		if N_PDU>0:
			count=-1;Message['PDUs']={};LTE_RRC=0;
			RRC_Comment=""
			while N_PDU>=0:
				temp_line=FH.next()
				if search("UL Data PDU Indication",temp_line,I):
					count+=1;N_PDU-=1;LTE_RRC=0;
					Message['PDUs']['PDU'+str(count)]={}
					Message['PDUs']['PDU'+str(count)]['NAS_Message']=""
				elif search("^\s*\[RNTI:\s+\d+\]",temp_line,I):
					Message['PDUs']['PDU'+str(count)]['RNTI']=int(temp_line.split(":")[1].split("]")[0].strip())
					CRC_Status=get_CRC(CRC_Message,Message['PDUs']['PDU'+str(count)]['RNTI'])
					Message['PDUs']['PDU'+str(count)]['CRC']=CRC_Status
				elif search("RNTI Type:",temp_line,I):
					rnti_type=temp_line.split(":")[1].strip().rstrip(']').split()[0]
					Message['PDUs']['PDU'+str(count)]['RNTI_TYPE']=sub("-","_",rnti_type)
				elif search("^\s*$",temp_line):
					break
				elif search("^\s+\w+\s+BSR\s+",temp_line,I):
					Message['PDUs']['PDU'+str(count)]['BSR']=temp_line.strip().split("BSR")[0].strip()+"_BSR"
					temp_line=FH.next()
					if search("^\s*.*Logical\s+channel\s+Group\s+id\s*:\s*\d+",temp_line,I):
						Message['PDUs']['PDU'+str(count)]['BSR']+=";LCG_ID:"+temp_line.split(":")[1].strip()
						temp_line=FH.next()
						if search("^\s*.*Buffer\s+size\s*:\s*",temp_line,I):
							Message['PDUs']['PDU'+str(count)]['BSR']+=";"+temp_line.split(":")[1].strip()
				elif search("^\s*.*Power\s+Headroom\s*\(PH.*\)\s*",temp_line,I):
					temp_line=FH.next();temp_line=FH.next()
					if search("^\s*.*Power\s+Headroom\s+Level\s*:\s*",temp_line,I):
						Message['PDUs']['PDU'+str(count)]['PHR']=temp_line.split(":")[1].strip()
				elif search("^\s+LTE\s+radio\s+resource\s+control\s+\(rrc\)\s+protocol",temp_line,I):
					LTE_RRC=1
				elif search("^\s*c1:\s*\w+\s*\(\d+\)",temp_line,I) and LTE_RRC==1:
					#print "ULSCH:"+temp_line,Frame_No
					Message['PDUs']['PDU'+str(count)]['UL_PHY_CH']="PUSCH"
					Message['PDUs']['PDU'+str(count)]['RRC_Message']=temp_line.split(":")[1].strip().split()[0]
					RRC_Comment+=temp_line
				elif search("^\s*nas\s+eps\s+\w+\s+management\s+message.*:\s+.*\(.*\)\s*",temp_line,I)and LTE_RRC==1:
					Message['PDUs']['PDU'+str(count)]['NAS_Message']+=temp_line.split(":")[1].split('(')[0].strip()+";" #NAS Message
				elif search("^\s*$|^\s*padding\s+data\s*:\s+\d+|^\s*MAC\s*:\s*",temp_line,I):
					LTE_RRC=0;
					break
				elif LTE_RRC==1:
					RRC_Comment+=temp_line;	
	Temp_Message={}
	N_PDU=Message['N_PDU']
	for key,value in Message.items():
		if key in ['PDUs','N_PDU']:
			continue
		else:
			Temp_Message[key]=value
	for no in range(N_PDU):
		for key,value in Message['PDUs']['PDU'+str(no)].items():
			Temp_Message[key]=value
		if ('RRC_Message' in Temp_Message) or ('BSR' in Temp_Message)or('PHR' in Temp_Message):
			writeToExcel(worksheet,row,format1,Temp_Message)
			if ('RRC_Message' in Temp_Message):
				worksheet.write_comment(row,Message_Header.index('RRC_Message'),RRC_Comment,{'x_scale': 4})
			RRC_Comment=""
			row=row+1
	del(Message,Temp_Message,N_PDU,Frame_No,count,no,LTE_RRC,CRC_Message)
	return row
###########################################################################
#	Function Name	:	RACH_IND
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	FH -> FileHandler
#					Frame -> Wireshark Frame Number
#					worksheet -> Current worksheet
#					row -> Current row in worksheet
#					format1 -> Format for writing data in a cell 
#	Return Value	:	Row Number
#	Description		:	This function collects all required information in Rach.Indication Message.
#					For each preamble it writes data into excel sheet after which row number has been returned to Driver.py
###########################################################################
def RACH_IND(FH,Frame,worksheet,row,format1):
	Message={};N_PRE=0;count=-1
	Message['PACKET_NUMBER']=Frame
	for line in FH:
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of Preamble:",line,I):
			Message['N_PRE']=int(line.split('(')[1].split(')')[0].rstrip())
			N_PRE=Message['N_PRE']
		if N_PRE>0:
			Message['PDUs']={};
			while N_PRE>=0:
				temp_line=FH.next()
				if search("RACH PDU INFO",temp_line,I):
					count+=1;N_PRE-=1
					Message['PDUs']['PDU'+str(count)]={}
					Message['PDUs']['PDU'+str(count)]['RACH_CONTENT']=""
				elif search("RA-RNTI:",temp_line,I):
					Message['PDUs']['PDU'+str(count)]['RNTI']=temp_line.split('(')[1].split(')')[0].rstrip()
					Message['PDUs']['PDU'+str(count)]['RNTI_TYPE']="RA_RNTI"
				elif search("Timing Advance:",temp_line,I):
					Message['PDUs']['PDU'+str(count)]['RACH_CONTENT']+="TA:"+temp_line.split('(')[1].split(')')[0].rstrip()+";"
				elif search("Preamble:",temp_line,I):
					Message['PDUs']['PDU'+str(count)]['RACH_CONTENT']+="Preamble:"+temp_line.split('(')[1].split(')')[0].rstrip()+";"
				elif search("^\s*$",temp_line):
					break
				else:
					continue
	Message['Msg_Type']="RACH_INDICATION"
	Message['UL_PHY_CH']="PRACH"
	N_PRE=Message['N_PRE']
	Temp_Message={}
	for key,value in Message.items():
		if key in ['PDUs','N_PRE']:
			continue
		else:
			Temp_Message[key]=value
	for no in range(N_PRE):
		for key,value in Message['PDUs']['PDU'+str(no)].items():
			Temp_Message[key]=value
		writeToExcel(worksheet,row,format1,Temp_Message)
		row=row+1
	del(Message,Temp_Message,N_PRE,no,count,Frame)
	return row
###########################################################################
#	Function Name	:	SRS_IND
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Inputs		:	FH -> FileHandler
#					Frame -> Wireshark Frame Number
#					worksheet -> Current worksheet
#					row -> Current row in worksheet
#					format1 -> Format for writing data in a cell 
#	Return Value	:	Row Number
#	Description		:	This function collects all required information in SRS.Indication Message.
#					For each UE it writes data into excel sheet after which row number has been returned to Driver.py
###########################################################################
def SRS_IND(FH,Frame,worksheet,row,format1):
	Message={};N_PDU=0;count=-1
	Message['PACKET_NUMBER']=Frame
	for line in FH:
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of Ue:",line,I):
			Message['N_PDU']=int(line.split("(")[1].split(")")[0])
			N_PDU=Message['N_PDU']
		if N_PDU>0:
			Message['PDUs']={}
			while N_PDU>=0:
				temp_line=FH.next()
				if search("SRS PDU Info",temp_line,I):
					count=count+1
					Message['PDUs']['PDU'+str(count)]={}
					N_PDU-=1;Message['PDUs']['PDU'+str(count)]['SRS']=""
				elif search("RNTI:",temp_line,I):
					Message['PDUs']['PDU'+str(count)]['RNTI']=temp_line.split("(")[1].split(")")[0]
					Message['PDUs']['PDU'+str(count)]['RNTI_TYPE']="C_RNTI"
				elif search("^\s+Num+\s+of\s+rb\s*:\s*0x.*\s*\(\d+\):",temp_line,I):
					key=temp_line.strip().split(":")[0];value=temp_line.strip().split(":")[1].split('(')[1].split(')')[0];
					Message['PDUs']['PDU'+str(count)]['SRS']+=key+":"+value+";"
				elif search("^\s+Rb\s+start\s*:\s*0x.*\s*\(\d+\)",temp_line,I):
					key=temp_line.strip().split(":")[0];value=temp_line.strip().split(":")[1].split('(')[1].split(')')[0];
					Message['PDUs']['PDU'+str(count)]['SRS']+=key+":"+value+";"
				elif search("^\s*SNR\s*:\s.*",temp_line,I):
					key=temp_line.strip().split(":")[0];value=temp_line.strip().split(":")[1].strip()
					Message['PDUs']['PDU'+str(count)]['SRS']+=key+":"+value+";"
				elif match("^\s*$",temp_line):
					break
				else :
					continue
	Message['Msg_Type']="SRS_INDICATION"
	N_PDU=Message['N_PDU']
	Temp_Message={}
	for key,value in Message.items():
		if key in ['PDUs','N_PDU']:
			continue
		else:
			Temp_Message[key]=value
	for no in range(N_PDU):
		for key,value in Message['PDUs']['PDU'+str(no)].items():
			Temp_Message[key]=value
		writeToExcel(worksheet,row,format1,Temp_Message)
		row=row+1
	del(Message,Temp_Message,N_PDU,no,count,Frame)
	return row
###########################################################################
#	Function Name	:	RX_SR_IND
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	FH -> FileHandler
#					Frame -> Wireshark Frame Number
#					worksheet -> Current worksheet
#					row -> Current row in worksheet
#					format1 -> Format for writing data in a cell 
#					UL_Q -> BUffer Queue of lenght 4 SF
#	Return Value	:	Row number 
#	Description		:	This funtion collects all information of RX_SR.Indication message.
#						For getting channel for SR it used UL_Q buffer(Same SF checking for RNTI and its corresponding Channel Type)
#					For each SR data has been written in Excel Sheet after which next row number has been returned to Driver.py
###########################################################################

def RX_SR_IND(FH,Frame,worksheet,row,format1,UL_Q):
	Message={};N_SR=0;count=-1
	Message['PACKET_NUMBER']=Frame
	for line in FH:
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of SR:",line,I):
			Message['N_SR']=int(line.split("(")[1].split(")")[0])
			N_SR=Message['N_SR']
		if N_SR>0:
			Message['PDUs']={}
			while N_SR>=0:
				temp_line=FH.next()
				if search("SR PDU INFO",temp_line,I):
					count=count+1
					Message['PDUs']['SR'+str(count)]={}
					N_SR-=1
				elif search("RNTI:",temp_line,I):
					Message['PDUs']['SR'+str(count)]['RNTI']=temp_line.split("(")[1].split(")")[0]
					Message['PDUs']['SR'+str(count)]['RNTI_TYPE']="C_RNTI"
					Message['PDUs']['SR'+str(count)]['UL_PHY_CH']=get_data_from_UL_Q(Message['SFN'],Message['SF'],"SR",Message['PDUs']['SR'+str(count)]['RNTI'],None,1,None,UL_Q)
				elif match("^\s*$",temp_line):
					break
				else :
					continue
	Message['Msg_Type']="RX_SR_INDICATION"
	N_SR=Message['N_SR']
	Temp_Message={}
	for key,value in Message.items():
		if key in ['PDUs','N_SR']:
			continue
		else:
			Temp_Message[key]=value
	for no in range(N_SR):
		for key,value in Message['PDUs']['SR'+str(no)].items():
			Temp_Message[key]=value
		writeToExcel(worksheet,row,format1,Temp_Message)
		row=row+1
	del(Message,Temp_Message,N_SR,no,count,Frame)
	return row
###########################################################################
#	Function Name	:	RX_CQI_IND
#	Author		:	Chandan	Kumar(chandan.kumar@votarytech.com)
#	Inputs		:	FH -> FileHandler
#					Frame -> Wireshark Frame Number
#					worksheet -> Current worksheet
#					row -> Current row in worksheet
#					format1 -> Format for writing data in a cell 
#					UL_Q -> BUffer Queue of lenght 4 SF
#	Return Value	:	Row Number
#	Description		:	This funtion collects all information of RX_CQI.Indication message.
#						For getting channel for SR it used UL_Q buffer(Same SF checking for RNTI and its corresponding Channel Type)
#					For each SR data has been written in Excel Sheet after which next row number has been returned to Driver.py
###########################################################################
def RX_CQI_IND(FH,Frame,worksheet,row,format1,UL_Q):
	Message={}
	Message['PACKET_NUMBER']=Frame
	for line in FH:
		count=-1;N_CQI=0
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of CQI:",line):
			Message['N_CQI']=int(line.split("(")[1].split(")")[0])
			N_CQI=Message['N_CQI']
		if 'N_CQI' in Message and N_CQI>0:
			Message['PDUs']={}
			while N_CQI>=0:
				temp_line=FH.next()
				if search("CQI PDU Indication",temp_line,I):
					count=count+1
					Message['PDUs']['CQI'+str(count)]={}
					N_CQI=N_CQI-1
				elif search("RNTI:",temp_line,I):
					Message['PDUs']['CQI'+str(count)]['RNTI']=(temp_line.split(":")[1].split('(')[1].split(')')[0])
				elif search("Timing Advance:",temp_line,I):
					Message['PDUs']['CQI'+str(count)]['TA']=temp_line.split(":")[1].split('(')[1].split(')')[0]
				elif search("UL CQI:",temp_line,I):
					value=int(temp_line.split(":")[1].split('(')[1].split(')')[0])
					db=-64+(value*0.5)
					Message['PDUs']['CQI'+str(count)]['CQI_PMI_INFO']="UL CQI:"+str(db)+"db("+str(value)+");TA:"+Message['PDUs']['CQI'+str(count)]['TA']
				elif search("RI:",temp_line,I):
					Message['PDUs']['CQI'+str(count)]['RI']=temp_line.split(":")[1].split('(')[1].split(')')[0]
				elif search("^\s*$",temp_line):
					break
				else:
					continue
	Message['Msg_Type']="RX_CQI_INDICATION"
	Message['RNTI_TYPE']='C_RNTI'
	N_CQI=Message['N_CQI']
	Temp_Message={}
	for key,value in Message.items():
		if key in ['PDUs','TA','N_CQI']:
			continue
		else:
			Temp_Message[key]=value
	for no in range(N_CQI):
		for key,value in Message['PDUs']['CQI'+str(no)].items():
			if key!='TA':
				Temp_Message[key]=value
		Temp_Message['UL_PHY_CH']=get_data_from_UL_Q(Message['SFN'],Message['SF'],"CQI",Temp_Message['RNTI'],None,1,None,UL_Q)
		writeToExcel(worksheet,row,format1,Temp_Message)
		row=row+1
	del(Message,Temp_Message,Frame,N_CQI,count)
	return row
###########################################################################
#	Function Name	:	writeToExcel
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Inputs		:	worksheet -> Current Worksheet
#					row -> Current row number
#					format1 -> Format with which data will be written in a cell
#					Message -> Dictionary which contains all required data captured for single row in Excel sheet.
#	Return Value	: 	None
#	Description		:	This function is for writing data into excel sheet at particular row.
#					The field of Message Dictionary should among the items of Message_Header.Otherwise it will throw key error.
###########################################################################
def writeToExcel(worksheet,row,format1,Message):
	for key,value in Message.items():
		worksheet.write(row,Message_Header.index(key),value,format1)	
###########################################################################
#	Function Name	:	createHeaderToExcel
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Inputs		:	worksheet -> Current Worksheet
#				:	format ->	Format used for writing data in Excel
#	Return Value	:	None
#	Description		:	This function is for creating Heading Lines in each worksheet.
###########################################################################
def createHeaderToExcel(worksheet,format):
	row=col=0
	Set_Cols={
	'PACKET_NUMBER':15,
	'Msg_Type':24,
	'SFN':5,
	'SF':5,
	'RNTI':9,
	'RNTI_TYPE':10,
	'RRC_Message':25,
	'NAS_Message':15,
	'DL_PHY_CH':10,
	'UL_PHY_CH':10,
	'CFI':5,
	'DL_DCI':7,
	'DL_PDCCH_INFO':15,
	'UL_DCI':7,
	'UL_PDCCH_INFO':10,
	'RACH_CONTENT':15,
	'RAR_CONTENT':15,
	'PHICH_INFO':15,
	'RI':8,
	'CQI_PMI_INFO':15,
	'DL_HARQ_TB_1':15,
	'DL_HARQ_TB_2':15,
	'SRS':10,
	'BSR':10,
	'PHR':10,
	'CRC':10
	}
	Merge_Info={
		'RNTI INFO':['RNTI','RNTI_TYPE'],
		'PHY_CHANNEL':['DL_PHY_CH','UL_PHY_CH'],
		'DL_DCI':['DL_DCI','DL_PDCCH_INFO'],
		'UL_DCI':['UL_DCI','UL_PDCCH_INFO'],
		'UCI_INFO':['RI','CQI_PMI_INFO'],
		'DL HARQ FEEDBACK':['DL_HARQ_TB_1','DL_HARQ_TB_2']
	}
	Merge_Data={
		'RNTI INFO':['RNTI VALUE','RNTI_TYPE'],
		'PHY_CHANNEL':['DL_PHY_CH','UL_PHY_CH'],
		'DL_DCI':['FORMAT','DCI_INFO'],
		'UL_DCI':['FORMAT','DCI_INFO'],
		'UCI_INFO':['RI','CQI_PMI_INFO'],
		'DL HARQ FEEDBACK':['DL_HARQ_TB_1','DL_HARQ_TB_2']
	}
	for i in Message_Header:
		worksheet.set_column(Message_Header.index(i),Message_Header.index(i),Set_Cols[i])
		worksheet.write(0,Message_Header.index(i),i,format)
		worksheet.write(1,Message_Header.index(i),"",format)
	for key,value in Merge_Info.items():
		worksheet.merge_range(0,Message_Header.index(value[0]),0,Message_Header.index(value[1]),key,format)
		worksheet.write(1,Message_Header.index(value[0]),Merge_Data[key][0],format)
		worksheet.write(1,Message_Header.index(value[1]),Merge_Data[key][1],format)
###########################################################################
#	Function Name	:	get_data_from_UL_Q	
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Inputs		:	sfn -> System Frame Number
#					sf ->	Subframe Number
#					pdu_type -> Type of PDU in which required information has to besearched.
#					get_rnit ->	 Calee function has passed a RNTI value (possible values RNTI/None)
#					send_rnti -> Calee function has requested a RNTI Value (its kind of flag Possible values 0/1)
#					send_channel -> Calee function has requested Channel Type (its kind of flag Possible values 0/1)
#					rb_start -> Calee function passed rb_start (Possible Value Rb_start/None)
#					UL_Q -> Buffer Queue
#	Return Value	:	Channel Type if send_channel set to 1 (CQI,SR,HARQ Indication)
#					RNTI		 if send rnti is set to 1 (In HI_DCI0 HI PDU need its RNTI )
#	Description		:	This function is used to get requested data from UL_Q buffer in particular SFN,SF.
#					First SFN,SF is searched. After that pdu_type is picked of that sfn,sf. In that PDU we look for required information
#					Requested information is returned to calee function.
###########################################################################
def get_data_from_UL_Q(sfn,sf,pdu_type,get_rnti,send_rnti,send_channel,rb_start,UL_Q):
	'''Args Description:
		sfn,sf=> SFN and SF of a Message(among message of UL_Q buffer) to be searched
		pdu_type(CQI/SR/ULSCH pdu) => Inside Message stucture(having various pdu ie HI,SR,CQI pdu),pdu_type indicate which pdu we have to look into
		get_rnti(rnti_value/None)=> This indicated that calee function has provided a rnti value
		send_rnti(0/1) => This indicated calee function expecting a rnti as return value
		send_channel => This indicated that calee function expecting channel type as return value
		rb_start => Calee function provided rb_start
		UL_Q => Buffer Queue
	'''
	pdu_list={};flag_sfn=flag_sf=0
	return_container="";
	for one_frame in UL_Q:
		for key,value in one_frame.items():
			if key=='SFN' and value==sfn:
				flag_sfn=1
			elif key=='SF' and value==sf:
				flag_sf=1
			if (flag_sfn & flag_sf)==1:
				pdu_list=one_frame[pdu_type]
				break
	if send_channel==1:
		for key,value in pdu_list.items():
			for key1,value1 in value.items():
				if key1=='RNTI'and value1==str(get_rnti):
					return_container=value['ULConfigPduType']
					break
		if search("_UCI_",return_container,I):
			return "PUCCH"
		elif search("_ULSCH_",return_container,I):
			return "PUSCH"
	elif send_rnti==1 and rb_start != None:
		for key,value in pdu_list.items():
			for key1,value1 in value.items():
				if key1=='RB Start' and value1==str(rb_start):
					return_container=value['RNTI']
					break
		return return_container
###########################################################################
#	Function Name	:	get_sfn_sf
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	SFN -> System Frame Number
#					SF ->	Subframe Number
#	Return Value	:	SFN,SF
#	Description		:	This function is for calculating SFN and SF 4 subframe back.
#					The calculated SFN and SF is returned to calee function.
###########################################################################
def get_sfn_sf(SFN,SF):
	SFN_R=SF_R=0;
	if (SF-4)<0:
		SFN_R=((SFN-1)+1024)%1024
	else:
		SFN_R=SFN
	SF_R=((SF-4)+10)%10
	return (SFN_R,SF_R)
###########################################################################
#	Function Name	:	get_CRC
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Inputs		:	CRC_Message -> A dictionary framed in CRC.Indication
#				:	rnti -> RNTI passed by RX_ULSCH.Indication 
#	Return Value	:	CRC_Flag
#	Description		:	This function finds the CRC_Flag of requested RNTI in CRC dictionary which has been framed in CRC.Indication Message.
###########################################################################
def get_CRC(CRC_Message,rnti):
	for count in range(CRC_Message['N_CRC']):
		#print CRC_Message['PDUs']['CRC'+str(count)]['RNTI'],rnti,CRC_Message['PDUs']['CRC'+str(count)]['CRC']
		if CRC_Message['PDUs']['CRC'+str(count)]['RNTI']==rnti:
			break
		else:
			continue
	CRC_flag=CRC_Message['PDUs']['CRC'+str(count)]['CRC']
	return CRC_flag
###########################################################################
#	FUnction Name	:	TX_REQ
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	FH -> FileHandler
#					Frame -> Wireshark Frame Number
#					worksheet -> Current worksheet
#					row -> Current row in worksheet
#					format1 -> Format for writing data in a cell
#					SIB_COmment -> Its a flag which indicate that SIB_COmment as been added to a current worksheet or not(We need only one SIB_Comment in a sheet)
#					MIB_COmment -> Its a flag which indicate that MIB_COmment as been added to a current worksheet or not(We need only one MIB_Comment in a sheet)
#	Return Value	:	Row Number,SIB_Comment and MIB_Comment 
#	Description		:	This funtion collects all information of TX_REQ message.
#					For each PDU data has been written in Excel Sheet after which next row number,SIB and MIB comment flag has been returned to Driver.py
###########################################################################
def TX_REQ(FH,Frame_No,worksheet,row,format1,SIB_Comment,MIB_Comment,SYS_BW):
	Message={};N_PDU=0
	Message['PACKET_NUMBER']=Frame_No
	Message['Msg_Type']="TX_REQUEST"
	for line in FH:
		if match("Frame\s+\d+\s*",line):
			break
		elif search("Sf:",line):
			Message['SF']=int(line.split(":")[1].rstrip())
		elif search("Sfn:",line):
			Message['SFN']=int(line.split(":")[1].rstrip())
		elif search("Num of PDU:",line,I):
			Message['N_PDU']=int(line.split("(")[1].split(")")[0].rstrip())
			N_PDU=Message['N_PDU']
		if N_PDU>0:
			RRC_Comment=""
			count=-1;Message['PDUs']={};LTE_RRC=0;SIB=0;N_SIB=0;RAR=0;Sibs=""
			while N_PDU>=0:
				temp_line=FH.next()
				if search("DL PDU INFO",temp_line,I):
					count+=1;N_PDU-=1;LTE_RRC=0;RAR=0;rar_content=""
					Message['PDUs']['PDU'+str(count)]={}
					Message['PDUs']['PDU'+str(count)]['NAS_Message']=""
				elif search("^\s*.?RNTI:",temp_line,I):
					Message['PDUs']['PDU'+str(count)]['RNTI']=temp_line.split(":")[1].strip().rstrip(']')
				elif search("RNTI Type:",temp_line,I):
					rnti_type=temp_line.split(":")[1].strip().rstrip(']').split()[0]
					Message['PDUs']['PDU'+str(count)]['RNTI_TYPE']=sub("-","_",rnti_type)
				elif search("^\s*$",temp_line):
					break
				elif search("^\s+LTE\s+radio\s+resource\s+control\s+\(rrc\)\s+protocol",temp_line,I):
					LTE_RRC=1
				elif search("^\s*BCCH-BCH-Message\s*$",temp_line,I) and LTE_RRC==1:
					Message['PDUs']['PDU'+str(count)]['DL_PHY_CH']="PBCH"; # MIB 
					Message['PDUs']['PDU'+str(count)]['RRC_Message']="MasterInformationBlock"
					RRC_Comment+=temp_line;
					del Message['PDUs']['PDU'+str(count)]['RNTI_TYPE']
				elif search("dl-Bandwidth:",temp_line,I) and LTE_RRC==1:
					DL_BW=int(temp_line.split(":")[1].split()[0].split('n')[1])
					if DL_BW != nRB[SYS_BW]:
						print('System bandwidth and nRB(MIB) Mismatch!!')
						_exit(1)
					P_Value=getP_Value(DL_BW)
				elif search("^\s*nas\s+eps\s+\w+\s+management\s+message.*:\s+.*\(.*\)\s*",temp_line,I)and LTE_RRC==1:
					Message['PDUs']['PDU'+str(count)]['NAS_Message']+=temp_line.split(":")[1].split('(')[0].strip()+";" #NAS Message
					RRC_Comment+=temp_line;
				elif search("^\s*c1:\s*systeminformation\s+\(\d+\)\s*$",temp_line,I) and LTE_RRC==1:
					SIB=1
				elif search("^\s*sib.?typeandinfo:\s+\d+\s+item\s*$",temp_line,I) and LTE_RRC==1 and SIB==1:
					Message['PDUs']['PDU'+str(count)]['N_SIB']=int(temp_line.split(":")[1].strip().split()[0])
					N_SIB=Message['PDUs']['PDU'+str(count)]['N_SIB']
					RRC_Comment+=temp_line;
					if N_SIB>0:
						Sibs=""
						while N_SIB>0:
							T=FH.next()
							RRC_Comment+=temp_line;
							if search("^\s*sib.?typeandinfo\s+item:\s+sib\d+\s*\(\d+\)\s*$",T,I):
								Sibs+=T.split(":")[1].split('(')[0].strip()+";" #Collecting Multiple SIB 
								N_SIB-=1
						Message['PDUs']['PDU'+str(count)]['RRC_Message']=Sibs.rstrip(';').upper()
						del Message['PDUs']['PDU'+str(count)]['N_SIB']
					Message['PDUs']['PDU'+str(count)]['DL_PHY_CH']="PDSCH"
				elif search("^\s*c1:\s*\w+\s*\(\d+\)",temp_line,I) and LTE_RRC==1:
					Message['PDUs']['PDU'+str(count)]['DL_PHY_CH']="PDSCH"
					Message['PDUs']['PDU'+str(count)]['RRC_Message']=temp_line.split(":")[1].split()[0].strip()
					RRC_Comment+=temp_line;
				elif search("^\s*RAR Headers:\s*",temp_line,I):
					RAR=1;
					Message['PDUs']['PDU'+str(count)]['DL_PHY_CH']="PDSCH"
					Message['PDUs']['PDU'+str(count)]['RRC_Message']="RAR"
					Message['PDUs']['PDU'+str(count)]['RAR_CONTENT']=""
				elif search("RAPID:\s+0x\d+\s*\(\d+\)\s*$",temp_line,I) and RAR==1:
					Message['PDUs']['PDU'+str(count)]['RAR_CONTENT']+="RAPID:"+temp_line.split("(")[1].split(')')[0]+";"
				elif search("Timing\s*Advance:",temp_line,I) and RAR==1:
					Message['PDUs']['PDU'+str(count)]['RAR_CONTENT']+="TA:"+temp_line.split(":")[1].strip()+";" #RAR content
				elif search("UL\s*Grant:",temp_line,I) and RAR==1:
					Message['PDUs']['PDU'+str(count)]['RAR_CONTENT']+="UL_Grant:"+temp_line.split(":")[1].strip()+";"
				elif search("^\s*Temporary\s*C-RNTI:",temp_line,I) and RAR==1:
					Message['PDUs']['PDU'+str(count)]['RAR_CONTENT']+="T_CRNTI:"+temp_line.split(":")[1].strip()
				elif search("^\s*.*cqi\s*request\s*:\s*\d+",temp_line,I):
					key="APERIODIC_CQI:";value=int(temp_line.split(':')[1].strip());value1="REQUESTED"
					if value==0:
						value1="NOT_REQUESTED"
					Message['PDUs']['PDU'+str(count)]['RAR_CONTENT']+=key+value1+";"
				elif search("^\s*$|^\s*padding\s+data\s*:\s+\d+|^\s*MAC\s*:\s*",temp_line,I):
					LTE_RRC=0;
					continue
				elif LTE_RRC==1:
					RRC_Comment+=temp_line;
	Temp_Message={}
	N_PDU=Message['N_PDU']
	put_comment=1
	for key,value in Message.items():
		if key in ['PDUs','N_PDU']:
			continue
		else:
			Temp_Message[key]=value
	for no in range(N_PDU):
		put_comment=1
		for key,value in Message['PDUs']['PDU'+str(no)].items():
			Temp_Message[key]=value
		if ('RRC_Message' in Temp_Message):
			if search("RAR",Temp_Message['RRC_Message'],I):
				Temp_Message['RRC_Message']="";put_comment=0
			writeToExcel(worksheet,row,format1,Temp_Message)
			if search("SystemInformationBlockType1",Temp_Message['RRC_Message'],I):
				if SIB_Comment==1:
					RRC_Comment="";put_comment=0
				else:
					SIB_Comment=1
			elif search("MasterInformationBlock",Temp_Message['RRC_Message'],I):
				if MIB_Comment==1:
					RRC_Comment="";put_comment=0
				else:
					MIB_Comment=1
			if put_comment==1:
				worksheet.write_comment(row,Message_Header.index('RRC_Message'),RRC_Comment,{'x_scale': 4})
			RRC_Comment=""
			row=row+1
	del(Message,Temp_Message,N_PDU,Frame_No,count,no,RAR,SIB,LTE_RRC,Sibs)
	return row,SIB_Comment,MIB_Comment;
###########################################################################
#	FUnction Name	:	getP_Value
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	n -> DL_Bandwidth in terms of RB
#	Return Value	:	P_Value
#	Description		:	This function calculate P_Value based on input provided
###########################################################################
def getP_Value(n):
	if n <=10:
		return 1
	elif n>=11 and n<=26:
		return 2
	elif n>=27 and n<=63:
		return 3
	elif n>=64 and n<=110:
		return 4
###########################################################################
#	FUnction Name	:	pcap2textConvert
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	file_name -> Pcap File Name
#	Return Value	:	Converted Text File name
#	Description		:	This function is for converting a wireshark capture file(pcap file)  into a text file.
#						COnverted Text file name is returned to calee function
###########################################################################
def pcap2textConvert(file_name):
	Log_File=file_name.split(".")[0]
	command="tshark -V -r "+file_name+ ">"+Log_File+".txt"
	system(command)
	return (Log_File+".txt")
###########################################################################
#	File Name		:	generateREADME
#	Author		:	Chandan Kumar(chandan.kumar@votarytech.com)
#	Input			:	None
#	Return Value	:	None
#	Description		:	This function is for generating README file in the current working directory.
###########################################################################
def generateREADME():
	readme="README.txt"
	if path.isfile(readme):
		return
	else:
		readme_fh=open(readme,"w")
		Data_to_write='''README::
Files included:
	1.Driver.py
	2.Functions.py
Prerequisite Software:
	1.Python (Link : https://www.python.org/downloads/)
	2.Xlsxwriter module for python (Link : https://pypi.python.org/pypi/XlsxWriter)
	3.tshark (If we are using pcap file as input) (Link https://www.wireshark.org/download.html)
	Note: Please check env PATH whether python and tshark are included or not. Make sure python and tshark is callable from anywhere.
Execution :
	1.Use command line argument.
		Example:
			$python Driver.py Log_file
	2. Supported Log_File_Format:
			Log_File.pcap | Log_File.txt | Log_File.log 
		Note: Please use some extension(pcap,log and text) to identify a pcap and text file
	3. In case of pcap file as input, we convert it into a text file then after parsing text file it will be deleted.
Output :
	1. Will give output as an Excel file with same name as Log_file having extension as .xlsx
	2. Depending upon "Max_row" (Driver.py),may have multiple sheet.
'''
		readme_fh.write(Data_to_write)
		readme_fh.close()

	

