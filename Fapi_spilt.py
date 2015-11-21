#!/usr/bin/python
from sys import platform,argv,exit
from re import search,I
from os import system,path
'''
Checking if the command line argument has been provided correctly or not
'''
Args_Error_1=0;Args_Error_2=0;
if len(argv)==3:
	File_Name=argv[1]
	Split_Size=argv[2]
	if search("\.pcap",File_Name,I):
		Args_Error_1=1
	if Split_Size.isdigit():
		Split_Size=int(Split_Size)
		Args_Error_2=1
	if (Args_Error_1 & Args_Error_2) ==0:
		exit('Two command line args is expected. ARGV[1] -> pcap file ARGV[2] ->  split size in MB')
else:
	exit('Two command line args is expected. ARGV[1] -> pcap file ARGV[2] ->  split size in MB')
'''
Checking whther you are using WIndows or Linux as commands are different in different platform
For Windows we are using two wireshark tool: 
	1. capinfos => to get the details of packet. with the help of capinfos tool we will calculate the number of split packet
	2. editcap => This tool splits the File into several file based on number of packet provided as argument
'''
if search("win32",platform,I):
	system("capinfos -cs "+File_Name+">Temp.txt") # Storing the pcap file info into temp file which will be deleted after its use
	try:
		FH=open("Temp.txt","r")
		File_Info={}
		for line in FH:
			k=line.rstrip().split(":")
			File_Info[k[0]]=k[1].strip()
		FH.close()
	except IOError:
		exit('Something Happened wrong!! A Temp.txt file should be generated. Please check permission of current folder!!')
	File_size=int(File_Info['File size'].split()[0])
	File_size_Format=File_Info['File size'].split()[1]
	No_Packets=int(File_Info['Number of packets'].split()[0])
	No_Packets_Format=File_Info['Number of packets'].split()[1]
	if search("K",File_size_Format,I):
		F_Multi=1024
	elif search("MB",File_size_Format,I):
		F_Multi=1024*1024
	elif search("GB",File_size_Format,I):
		F_Multi=1024*1024*1024
	if search("K",No_Packets_Format,I):
		P_Multi=1024
	elif search("MB",No_Packets_Format,I):
		P_Multi=1024*1024
	elif search("GB",No_Packets_Format,I):
		P_Multi=1024*1024*1024
	File_size=File_size*F_Multi
	No_Packets=No_Packets*P_Multi
	#system("del Temp.txt")	#Deleteing temporary file
	Split_Size=Split_Size*1024*1024  #Converting Split_Size(Which is in MB ) into Bytes
	if File_size<=Split_Size:		# If File size is less than split size then no need to split only one file will be generated 
		Split_Size=File_size
	No_Split=File_size/Split_Size
	if (No_Split-(int(No_Split))) > 0.5:
		No_Split=int(No_Split)+1
	else:
		No_Spilt=int(No_Split)
	Packet_size=No_Packets/No_Split
	if Packet_size-int(Packet_size) > 0.5:
		Packet_size=int(Packet_size)+1
	else:
		Packet_size=int(Packet_size)
	File_Name_split=File_Name.split(".")[0]
	if path.exists(File_Name_split):
		system("del /Q "+File_Name_split+"\\*")
	else:
		system("mkdir "+File_Name_split)	#create a directory where we store all splited file
	system("editcap -c "+str(Packet_size)+" "+File_Name+" "+File_Name_split+"\\"+File_Name) # Spliting files using editcap
elif search("linux",platform,I):
	File_Name_split=File_Name.split(".")[0]
	if path.exists(File_Name_split):
		system("del /Q "+File_Name_split+"\\*")
	else:
		system("mkdir "+File_Name_split)	#create a directory where we store all splited file
	system("tcpdump -r "+File_Name+" -C "+str(Split_Size)+" -w "+File_Name_split+"/"+File_Name)

	
