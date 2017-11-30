#!/usr/bin/env python
import socket
import re
import os, sys, socket, struct, select, time, threading
import thread
from cipher.chacha_poly import ChaCha
from cipher.ecc import string_to_int
from cipher.curves import SECP256k1
from os import urandom

# HOST = socket.gethostbyname(socket.gethostname())
##The pinging part starts here
ICMP_ECHO_REQUEST = 8


def checksum(source_string):
    sum = 0
    countTo = (len(source_string) / 2) * 2
    count = 0
    while count < countTo:
        thisVal = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2

    if countTo < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def send_one_ping(my_socket, dest_addr, ID, onlydata):
    data = "@@" + onlydata
    dest_addr = socket.gethostbyname(dest_addr)
    my_checksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    bytesInDouble = struct.calcsize("d")
    # my_checksum = checksum(header + data)
    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
    )
    packet = header + bytes(data, 'utf-8')
    my_socket.sendto(packet, (dest_addr, 1))  # Don't know about the 1


def do_one(dest_addr, timeout, payload):
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error:
        print("error at do_one \n")
        raise  # raise the original error

    my_ID = os.getpid() & 0xFFFF

    send_one_ping(my_socket, dest_addr, my_ID, payload)
    my_socket.close()
    return delay


# The sniffer part starts here..!!!
def startsniffing():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(("", 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print("Sniffer Started.....")
    while 1:
        data = s.recvfrom(65565)
        d1 = str(data[0])
        d2 = str(data[1])
        data1 = re.search('@@(.*)', d1)
        datapart = data1.group(0)
        # print datapart
        print(">:" + datapart)
        reader()

def keyAgreement(mod, mySecret, userPublic):
	return (userPublic ** mySecret) % mod

def createPublic(mod, base, mySecret):
	return (base ** mySecret) % mod

def encrypt(message, sharedKey):
	cha = ChaCha(sharedKey)
	return cha.encrypt(message)

def decrypt(message, sharedKey):
	cha = ChaCha(sharedKey)
	cha.decrypt(message)
	return 0

def main():
    knownUsers = {}
    myUser = null
    while True:
        toClean = raw_input("command: ")
        command = toClean.strip()
        if(command[:4] == "exit"):
            print("exiting program, bye...")
            break
        elif(command[:5] == "-user"):
            myUser = knownUsers[getpass.getpass("Username: ").strip()]
        elif(command[:5] == "--new"):
            #for optimal security we would calculate a random mod and base that
            #match
            newUser = User(null, 23, 5, random.randint(1000, 9999), -1)
            values = command.split(" ")
            newUser.setName(values[values.index("-user")+1]
            if("-gen" in command):
                #create new key for the user
                curve = SECP_256k1()
                privateKey = string_to_int(os.urandom(curve.coord_size)[:4])
                newUser.setShared(privateKey)
            else:
                newUser.setShared(getpass.getpass("Input your private key: "))
            knownUsers[newUser.getName()] = newUser
        elif(command[:3] == "-eU"):
            rest = command[3:].strip()
            tempUser = User(null, -1, -1, -1, -1)
            #-name -mod -base -pub -shared
            things = rest.split(" ")
            while(len(things) > 0):
                temp = things.pop(0)
                if(temp == "-name"):
                    tempUser.setName(things.pop(0))
                elif(temp == "-mod"):
                    tempUser.setMod(things.pop(0))
                elif(temp == "-base"):
                    tempUser.setBase(things.pop(0))
                elif(temp == "-pub"):
                    tempUser.setPub(things.pop(0))
                elif(temp == "-shared"):
                    tempUser.setShared(things.pop(0)) 
                elif(temp == "-myPub"):
                    tempUser.setShared(things.pop(0))
            if(tempUser.getName() in knownUsers):
                targetUser = knownUsers[tempUser.getName()]
                if(tempUser.getMod() > 0):
                    targetUser.setMod(tempUser.getMod())
                if(tempUser.getBase() > 0):
                    targetUser.setBase(tempUser.getBase())
                if(tempUser.getPub() > 0):
                    targetUser.setPub(tempUser.getPub())
                if(tempUser.getShared() > 0):
                    targetUser.setShared(tempUser.getShared())
            else:
                knownUsers[tempUser.getName()] = tempUser     
        elif(command[:6] == "-agree"):
            values = command.split(" ")
            user = knownUsers[values[values.index("-u") + 1]] 
            user.setShared(keyAgreement(user.getMod(), myUser.getShared(), user.getPub())
        elif(command[:5] == "-load"):
            a
         	
    try:
		print("sniff")
		#thread.start_new_thread(startsniffing, ())
	except:
		print("error starting thread")
	
	ip = raw_input("Enter the destination IP: ")
	delay = 1
    while True:
        temp = raw_input("")
        message = encrypt(temp, sharedSecret)
        if (temp == "exit"):
            break
        do_one(ip, delay, encrypted)

main()
