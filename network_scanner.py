#-----network scanner tool-----------

import nmap

def menu():
	print("----------------Main Menu-----------------")
	print("1.Scan single host")
	print("2.Scan range")
	print("3.Scan network")
	print("4.Agressive scan")
	print("5.Scan ARP packet")
	print("6.Scan all port only")
	print("7.Scan in verbose mode")
	print("8.Exit")


def Scan_single_host():

    nm = nmap.PortScanner() 
    ip_address = input("\tEnter the IP : ")
    print("Wait.......................")
    try:
        scan = nm.scan(hosts=ip_address,ports="1-100",arguments = "-v -sS -O -Pn") 
        for host in scan["scan"][ip_address]['tcp'].items():
            print("Tcp Port",host[0])
            print("State:",host[1]['state'])
            print("Reason:",host[1]['reason'])
            print("Name:",host[1]['name'])		
    except:
        print("Use sudo ")


def Scan_range():

    nm = nmap.PortScanner()
    ip_address = input("\tEnter the IP : ")
    print("Wait........................")
    try:
        scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")
        for host in scan["scan"]:
            print("Ip range:",host)
    except:
        print("Use sudo ")

def Scan_network():

    nm = nmap.PortScanner() 
    ip_address = input("\tEnter the IP : ")
    print("Wait........................")
    try:
        scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn")

        for i in scan["scan"][ip_address]['osmatch']:
            print(f"Os Name : {i['name']}")
            print(f"Line : {i['line']}")
            for j in i['osclass']:
                print(f"Os-Type :",{j['type']})
                print(f"osgen :",{j['osgen']})
    except:
        print("Use sudo ")

def Agressive_scan():

    nm = nmap.PortScanner() 
    ip_address = input("\tEnter the IP : ")
    print("Wait........................")
    try:
        scan = nm.scan(hosts=ip_address,arguments = "-sS -O -Pn -T4")
        for i in scan["scan"][ip_address]['osmatch']:
            print(f"Os Name : {i['name']}")
            print(f"Line : {i['line']}")
            for j in i['osclass']:
                print(f"Os-Type :",{j['type']})
                print(f"osgen :",{j['osgen']})
    except:
        print("Use sudo ")


def Scan_ARP_packet():
    nm = nmap.PortScanner() 
    ip_address = input("\tEnter the IP : ")
    print("Wait........................")
    try:
        scan = nm.scan(hosts=ip_address,arguments = "-sS -O -PR")
        for i in scan["scan"][ip_address]['osmatch']:
            for j in i['osclass']:
                print(f"cpe : {j['cpe']}")
                print(f"osfamily : {j['osfamily']}")
    except:
        print("Use sudo ")


def Scan_All_ports():
    nm = nmap.PortScanner() 
    ip_address = input("\tEnter the IP : ")
    print("Wait........................")
    try:
        scan = nm.scan(hosts = ip_address,ports = "1-2",arguments = "-sS -O -Pn")
        for port in scan["scan"][ip_address]['tcp'].items():
            print("Tcp Port :",port[0])
            print("State :",port[1]['state'])
            print("Name :",port[1]['name'])
            print("conf :",port[1]['conf'])
    except:
        print("Use sudo ")


def Scan_in_verbose_mode():
    nm = nmap.PortScanner() 
    ip_address = input("\tEnter the IP : ")
    print("Wait........................")
    try:
        scan = nm.scan(hosts = ip_address,arguments = "-sS -O -Pn -v")
        for i in scan["scan"][ip_address]['osmatch']:
            print(f"name :{i['name']}")
            print(f"accuracy : {i['accuracy']}")
            print(f"osclass : {i['osclass']}")
    except:
        print("Use sudo ")
		

while True:
	menu()
	ch =  int(input("Enter your choice: "))
	if ch == 1:
		Scan_single_host()
	elif ch == 2:
		Scan_range()
	elif ch == 3:
		Scan_network()
	elif ch == 4:
		Agressive_scan()
	elif ch == 5:
		Scan_ARP_packet()
	elif ch == 6:
		Scan_All_ports()
	elif ch == 7:
		Scan_in_verbose_mode()
	elif ch == 8:
		break;
	else:
		print("invalid Choice")