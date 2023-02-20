import nmap
#Created by Marco Jameson Pangilinan
#Montrer - NMAP Scanning Extension Tool
#Version 1.0 

import argparse
from argparse import RawTextHelpFormatter
import json
import ipaddress
from tabulate import tabulate
import time
from pyfiglet2 import *
import sys


#function that handles the command line arguments and options created by user

def argParser():
	parser = argparse.ArgumentParser('Montrer - The Nmap Port Scanner Extension Tool. Written In Python')
	
	parser.add_argument('host', type=str,  help='Enter the IP address or range of IP address that you would want to be scanned.  ACCEPTED FORMATS: X.X.X.X |  X.X.X.X-X')
	parser.add_argument('-p', '--port', type=str, required = True, help='Input the port number that you wish to be scanned. Enter a port number ranging from 0- 65535')
	parser.add_argument('-v' , action = 'version', version = ' %(prog)s - version 1.0. Created by Marco Jameson Pangilinan. Montrer is an Nmap extension tool that displays Nmap ICMP and TCP scan results in a tabular and presentable format. Montrer is the french word for the verb display. Must have the following pre-requistes (installed in root): running in python3, python-nmap, python-pip argparse module, json module, ipaddress module, tabulate module, time module, pyfiglet2 module, and sys module', help = 'Shows the current version of Montrer')
	
	parser.add_argument('-t', action='store_true', help='If you would want to know how long it took for the program to finish scanning, you may include this option at the end')
	
	args = parser.parse_args()
	
	return args

#function that actually does the scanning; returns the list containing the result of one scan
			
def actualScanner(host,port):
	try:
		nmapScan = nmap.PortScanner()

		hostEntry = []
		
		hostEntry.append(str(host))
		
		#ICMP Test
		nmapScan.scan(host, arguments='-n -sP -PE -PA')
		try:
			if nmapScan[host]['status']['state']:
				hostEntry.append("\u2b06")
		except:
			hostEntry.append("\u2b07")
		
		
			
		#TCP Connect
		nmapScan.scan(host, port, arguments='-PN -sT')
		try:
			if nmapScan[host]['tcp'][int(port)]['state'] == "open":
				hostEntry.append("\u25cb")
			elif nmapScan[host]['tcp'][int(port)]['state'] == "filtered":
				hostEntry.append("\u25c6")
			else:
				hostEntry.append("\u25cf")
		except:
			hostEntry.append("\u2b07")
		
		
			
		#TCP SYN	
		nmapScan.scan(host, port, arguments='-PN -sS')
		try:
			if (nmapScan[host]['tcp'][int(port)]['state']) == "open":
				hostEntry.append("\u25cb")
			elif (nmapScan[host]['tcp'][int(port)]['state']) == "filtered":
				hostEntry.append("\u25c6")
			else:
				hostEntry.append("\u25cf")
		
		except:
			hostEntry.append("\u2b07")
			
		
		#TCP XMAS
		nmapScan.scan(host, port, arguments='-PN -sX')
		try:
			if (nmapScan[host]['tcp'][int(port)]['state']) == "open|filtered":
				hostEntry.append("\u25cb |\u25c6")

			else:
				hostEntry.append("\u25cf")
		
		except:
			hostEntry.append("\u2b07")
		
			
			
		#TCP FIN
		nmapScan.scan(host, port, arguments='-PN -sF')
		try:
			if (nmapScan[host]['tcp'][int(port)]['state']) == "open|filtered":
				hostEntry.append("\u25cb |\u25c6")

			else:
				hostEntry.append("\u25cf")
		
		except:
			hostEntry.append("\u2b07")

		
		#TCP Null
		nmapScan.scan(host, port, arguments='-PN -sN')
		try:
			if (nmapScan[host]['tcp'][int(port)]['state']) == "open|filtered":
				hostEntry.append("\u25cb |\u25c6")

			else:
				hostEntry.append("\u25cf")
		
		except:
			hostEntry.append("\u2b07")
		
		
		#TCP ACK
		nmapScan.scan(host, port, arguments='-PN -sA')
		try:
			if (nmapScan[host]['tcp'][int(port)]['state']) == "filtered":
				hostEntry.append("\u25c6")

			else:
				hostEntry.append("\u25c7")
		
		except:
			hostEntry.append("\u2b07")
		
		return hostEntry #returns the list containing the result of one scan
	except (KeyboardInterrupt):
		print("Program Stopped Abruptly..")
		print("Au Revoir!")	
		sys.exit()	
			
			
#function that is executed by the thread, collates the result from the actual scanner
def nmapScan(targetHost, targetPort, timeOption, starttime):

		try:
			#headers for the tabulated results
			headers = ["Hostname", "ICMP", "TCP Connect", "TCP SYN", "TCP XMas", "TCP FIN", "TCP NULL", "TCP ACK"]
			
			#separates the scan for single host and range host
			if len(targetHost)==1:
				hostCollection = [] #will eventually hold the results 
				hostEntry = actualScanner(targetHost[0], targetPort) #calls the actualScanner function to execute the scan
				
				
				hostCollection.append(hostEntry) #appends the result to the results list
				
				print("\nPort Number: %s" % targetPort) #prints the port targeted
				print(tabulate(hostCollection,headers,tablefmt="fancy_grid")) #displays result in tabular form
				
				
				
			else:
				startIP = targetHost[0] #assigns starting ip for scan
				endIP = targetHost [1] #assigns ending ip for scan
				temp = startIP #assigns a temporary holder for ip to be manipulated

				hostCollection = [] #will eventually hold all results
				hostEntry = [] #holds one result at a time
				while int(ipaddress.IPv4Address(temp)) <= int(ipaddress.IPv4Address(endIP)):
					hostEntry = actualScanner(temp, targetPort)
					
					hostCollection.append(hostEntry)
					
					#statements that iterates the ip address
					temp = int(ipaddress.IPv4Address(temp)) + 1
					temp = str(ipaddress.IPv4Address(temp))
					
				print("\nPort Number: %s" % targetPort) #prints the target port
				print(tabulate(hostCollection,headers,tablefmt="fancy_grid")) #displays result in tabular form
			
			#display time if desired by user
			if timeOption:
				print("\nMontrer finished in %s seconds\n" % (time.time() - starttime))
		except (KeyboardInterrupt, TypeError):
			print("Program Stopped Abruptly..")
			print("Au Revoir!")	
			sys.exit()
				
		
#function that displays the legends for the scan tool for easier understanding of the output			
def scanLegends():

	print('=====================================================================================================')
	print("Types of Scanning and their possible outputs\n")
	print("\nICMP Scanning")
	print("\t \u2b06 : Responds to Echo Requests")
	print("\t \u2b07 : No Response")
	print("\nTCP Connect & TCP SYN")
	print("\t \u25cb : Port is OPEN")
	print("\t \u25c6 : Port is FILTERED")
	print("\t \u25cf : Port is CLOSED")
	print("\t \u2b07 : Host is DOWN")
	print("\nTCP XMAS, TCP FIN, & TCP NULL")
	print("\t \u25cb |\u25c6 : Port is OPEN|FILTERED")
	print("\t \u25cf : Port is CLOSED")
	print("\t \u2b07 : Host is DOWN")
	print("\nTCP ACK")
	print("\t \u25c6 : Port is FILTERED")
	print("\t \u25c7 : Port is UNFILTERED")
	print("\t \u2b07 : Host is DOWN")
	print('=====================================================================================================')

#function to check whether ports are inside the valid range (0-65535)	
def portValidation(port):
	if (int(port)>=0 and int(port)<=65535):
		print("Port number is valid!")
		return True
	else:
		print("Port number is invalid! Please select a port number from 0 - 65535")
		return False
		
#function to check whether the host/s are of valid format. Accepted Formats X.X.X.X or X.X.X.X-X		
def hostValidation(host):
	targetHost = []
	tempHostHolder = []
	rangeHolder = []
	x=0
	value = True
	
	if str(host).find("-") != -1:
			tempHostHolder = str(host).split("-")
			targetHost.append(tempHostHolder[0])
			rangeHolder = tempHostHolder[0].rsplit(".", 1)
			targetHost.append(rangeHolder[0] + "." + tempHostHolder[1])
						
	else:
			targetHost.append(str(host))
		
	for x in targetHost:
			
			try:
				ipaddress.ip_address(x)
			except ValueError:
				value = False
				
	
	
	if value:
		print("IP Address/es is/are valid!")
		return True
	else:
		print("IP Address/es is/are invalid! Please follow this format: \n\t X.X.X.X - for single host \n\t X.X.X.X-X for range of hosts")
		return False
	
if __name__ == '__main__':

	try:
		print('=====================================================================================================')	
		starttime = time.time() #Starts timer for the program
		figlet_color.cyan("Montrer", 'broadway') #banner for program
		print('=====================================================================================================')
			
		argStat = argParser() #Calls argument parser and collects input from user
			
		if(portValidation(argStat.port)):
			if(hostValidation(argStat.host)):
			
				#lists created for ip address handling
				targetHost = []
				tempHostHolder = []
				rangeHolder = []
				
				#this determines the starting point and ending point of range input, also separates range and non range
				if str(argStat.host).find("-") != -1:
					tempHostHolder = str(argStat.host).split("-")
					targetHost.append(tempHostHolder[0])
					rangeHolder = tempHostHolder[0].rsplit(".", 1)
					targetHost.append(rangeHolder[0] + "." + tempHostHolder[1])
							
				else:
					targetHost.append(str(argStat.host))
				
				#assigns target port and time option to variables to be used later	
				targetPort = argStat.port
				timeOption = argStat.t
				
				
				
				
				#alerts user that scan is starting
				print('=====================================================================================================')
				print('Starting scan...')
				print('=====================================================================================================')
				
				#displays scan legends for easier understanding of output
				scanLegends()
				print('=====================================================================================================')
				
				#starts thread for scan
				
				nmapScan(targetHost, targetPort, timeOption, starttime)
						
	except (KeyboardInterrupt, IOError,TypeError):
		
		print("Program Stopped Abruptly..")
		print("Au Revoir!")	
		sys.exit()

		
	
