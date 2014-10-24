#!/usr/bin/python
# Writen by Jerome KIEFFER, part of the sesame project (GPL)
# big library that includes all the little functions needed by the other 
# python programs of sesame-
#
#functions defined : 
# arptable(file,interface): "read the arp table on the computer, return a contable (without user or time)" 
# contable(file): "returns the table of (still) connected computers"
# def writetable(contable): "write the contable in the file /etc/connected (and restarts the firewall)
# def buildfw(contable): "rebuild the firewall according to the contable passed as option"
# def getcoord(ip): "return info like [MAC, IP, user, start time ] "
# def print_headers(): : just prints the headers for a html file.
# def error(file): "print an error message/page to stdout and quit"
# def LogAndDec(macip):	"log the deconnection and return the connection time"
# def get_MAC(IP): "returns the MAC address of a given IP (according to the ARP table)"
# def generatePassword(passwd_size):"Generates a password of the given length"
	

home="/usr/local/sesame"
connected=home+"/etc/connected"
arp="/proc/net/arp"
iface="eth1"
passwd=home+"/etc/passwd"
log=home+"/log/"
iface="eth1"
import os,time,sys,random,string
chain="wlan-inet"
iptables="sudo /sbin/iptables"

def readticket(file):
	tickettab=[]
	f=open(file,"r")
	for lignes in f.readlines():
		tickettab.append(lignes.split(";"))
	f.close()
	return tickettab

def update_ticket(user,time,file=home+"/etc/ticket"):
	"""removes the given time to the ticket"""
	table=readticket(file)
	f=open(file,"w")
	rest=0
	for ligne in table:
		if ligne[0]==user:
			rest=float(ligne[2])-time
			if rest>0:f.write("%s;%s;%s\n"%(ligne[0],ligne[1],rest))
		else:
			if len(ligne)==3:f.write("%s;%s;%s\n"%(tuple(ligne)))
	if rest<0:rest=0
	rest=int(rest)
	return rest	

def get_MAC(IP):
	"""returns the MAC address of a given IP"""
	arplist=arptable(iface=iface)
	MAC=""
	for macip in arplist:
		if IP==macip[1]:MAC=macip[0]
	return MAC

def generatePassword(passwd_size=6):
    """Generates a password of the given length"""
    chars = string.letters #+ string.digits
    passwd = ""
    for x in range(passwd_size):
        passwd += random.choice(chars)
    return passwd
							
def arptable(file="/proc/net/arp",iface="eth0"):
	"read the arp table on the computer, return a contable (without user or time)"
	arplist=[]
	f=open(file,"r")
	for ligne in f.readlines():
		chaine=ligne.split()
		if chaine[5]==iface:
			macip=[chaine[3],chaine[0]]
			arplist.append(macip)
	f.close()
	return arplist

def contable(file):
	"returns the table of (still) connected computers"
	contable=[]
	f=open(file,"r")
	for ligne in f.readlines():
		contable.append(ligne.split())
	f.close
	return contable

def writetable(contable):
    f=open(connected,"w")
    for macip in contable:
	    f.write(macip[0]+"   "+macip[1]+"	"+macip[2]+"	"+macip[3]+"\n")
    f.close
    os.popen("chown www-data "+connected,"r")
#on finit par regenerer le firewall
    buildfw(contable)



def buildfw(contable):
	"rebuild the firewall according to the contable passed as option"
	os.popen(iptables+" -F "+chain,"r")
	for macip in contable:
		os.popen(iptables+" -t nat -D PREROUTING -i eth1 -s "+macip[1]+' -p tcp -m tcp --dport 80 -j DNAT --to 192.168.100.254',"r")
		os.popen(iptables+" -t nat -D POSTROUTING -d "+macip[1]+' -p tcp -m tcp --dport 80 -j SNAT --to 192.168.100.254',"r")

		os.popen(iptables+" -A "+chain+" -m mac --mac-source "+macip[0]+" -s "+macip[1]+' -j ACCEPT',"r")
	os.popen(iptables+" -A "+chain+" -j ULOG --ulog-prefix 'WIFI reject '","r")    
	os.popen(iptables+" -A "+chain+" -j REJECT","r")



def getcoord(ip):
	"recupere le nom, l'IP et la MAC, depuis l'IP"
	macip=[]
	f=open(connected,"r")
	for ligne in f.readlines():
		chaine=ligne.split()
		if chaine[1]==ip:macip=chaine
	f.close
	return macip

def print_headers():
	print "Content-Type: text/html; charset=ISO-8859-1"
	print
		

def error(file=home+"/htdocs/logout-error.html"):
	"print an error message to stdout and quit"
	print_headers()
	print open(file).read()
	sys.exit(0)
	
def LogAndDec(macip):
	"log the deconnection and calculate the connection time"
	now=time.time()
	date=time.strftime('%a, %d %b %Y %H:%M:%S', time.localtime())
	duree=int(now-float(macip[3])) #une precision a la seconde vous va ?
	os.popen(iptables+" -t nat -A PREROUTING -i eth1 -s "+macip[1]+' -p tcp -m tcp --dport 80 -j DNAT --to 192.168.100.254',"r")
	os.popen(iptables+" -t nat -A POSTROUTING -d "+macip[1]+' -p tcp -m tcp --dport 80 -j SNAT --to 192.168.100.254',"r")
	open(log+macip[2]+".log","a").write(date+" : Deconnection user="+macip[2]+" IP="+macip[1]+" MAC="+macip[0]+" time="+str(now)+" \n"+date+" : Connection_time="+str(duree)+" seconds \n")
	return duree

