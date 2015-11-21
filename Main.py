#!/usr/bin/python
from sys import argv,exit
from os import system,listdir
from commands import getoutput
PCAP_FILE=argv[1]
List_Split=[]
def pcap_Menu(PCAP_FILE):
	while True:
		print "Choose Option:\n\t1.Split PCAP File\n\t2.Use Single File Only\n\t3.Exit"
		Split_Option=raw_input('Enter your choice : ')
		if Split_Option.isdigit():
			Split_Option=int(Split_Option)
		else:
			print "Choose Option properly!! Enter digit only"
		if Split_Option==1:
			split_size=input('Enter Split size of pcap in MB')
			
			for file in listdir('Test/'):
				print "Processing "+file+" ...."
				p=getoutput('python Driver.py Test/'+file)
				if p=='1':
					print "Done!"
			break
		elif Split_Option==2:
			system("python Driver.py "+PCAP_FILE)
			break
		elif Split_Option==3:
			exit('\nThank you !!\n')
		else:
			print "Choose correct option!!"
if __name__=='__main__':
	pcap_Menu(PCAP_FILE)


