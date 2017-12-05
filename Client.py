#!/usr/bin/env python
import socket
import re
import os, sys, socket, struct, select, time, threading
import thread
import getpass
import pickle
from User import User
from cipher.chacha_poly import ChaCha
from cipher.ecc import string_to_int, int_to_string
from cipher.curves import SECP_256k1
from os import urandom
from random import randint

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

def helpAll():
    totalHelp = ""
    totalHelp += "___________________________________________________________\n"
    totalHelp += helpNew()
    totalHelp += "___________________________________________________________\n"
    totalHelp += helpLoad()  
    totalHelp += "___________________________________________________________\n"
    totalHelp += helpSave()  
    totalHelp += "___________________________________________________________\n"
    totalHelp += helpEdit()
    totalHelp += "___________________________________________________________\n"
    totalHelp += helpAgree()
    totalHelp += "___________________________________________________________\n"
    return totalHelp

def helpNew():
    help = ""
    help += "+-------+\n"
    help += "| --new |\n"
    help += "+-------+\n"
    help += "Cretes a new user for you with a new private key.\n\n"
    help += "-user: Username you wish to save this account to\n"
    help += "-gen: Signals whether you want a randomly generated\n"
    help += "\tkey or you wish to enter your own key. If this flag\n"
    help += "\tis not present you will be asked to input your key.\n"
    return help

def helpEdit():
    help = ""
    help += "+-------+\n"
    help += "|  -eU  |\n"
    help += "+-------+\n"
    #-name -mod -base -pub -shared
    help += "The name flag is required. If the user specified by\n"
              #1234567890123456789012345678901234567890123456789012
    help += "\tthe name flag then the values will be updated based\n"
    help += "\ton the information given by the flags. Otherwise, a\n"
    help += "\tnew user will be created. In the case of a new user\n"
    help += "\tall fields are required except the shared value.\n"
    help += "-name: The name of the user to create or change\n"
    help += "-mod: Value used in modular divison in Diffie-Hellman\n" 
    help += "-base: Base for the exponential multiplication in\n"
    help += "\tDiffie-Hellman\n"
    help += "-pub: Public key of the user you are speaking to\n"
    help += "-shared: Shared secret between you and user\n"
    return help
    
def helpAgree():
    help = ""
    help += "+-------+\n"
    help += "|-agree |\n"
    help += "+-------+\n"
    return help

def helpSave():
    help = ""
    help += "+-------+\n"
    help += "| -save |\n"
    help += "+-------+\n"
    return help

def helpLoad():
    help = ""
    help += "+-------+\n"
    help += "| -load |\n"
    help += "+-------+\n"
    return help

def threadSniffer():
    global mailBox
    global seen
    global knownUsers
    global myUser
    global outUser
    global verified

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(("", 0))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    print("Sniffer Started.....")
    while 1:
        data = s.recvfrom(65565)
        #actual message
        d1 = str(data[0])
        #sender data
        d2 = str(data[1])
        
        values = d0.split("||")
        if(d2 not in seen):
            userName = values[values.index("user") + 1]
            seen[d2] =  [userName, -1]
            if(userName in knownUsers.keys()):
                targetUser = knownUsers[userName]
                encDemand = values[values.index("auth") + 1]
                demand = decrypt(encDemand, targetUser.getShared())
                ruth = encrypt(eval(demand), targetUser.getShared())
                authPair = authenticate(10)
                seen[d2][1] = authPair[1]
                encReq = encrypt(authPair[0], targetUser.getShared())
                sending = "||user||" + outUser + "||auth||" + encReq
                sending += "||ruth||" + ruth + "||"
                mailbox[userName] = []
                do_one(d2, 11, sending)
            else:
                do_one(d2, 1, "invalid")
        elif(seen[d2][1] != -100.10233):
            userName = seen[d2][0]
            if(userName not in knownUsers.keys()):
                break
            targetUser = knownUsers[userName]
            temp = decrypt(d1[d1.index("@@") + 2:], targetUser.getShared())
            newVals = temp.split("||")
            sending = ""
            if("auth" in newVals):
                encDemand = newVals[newVals.index("auth") + 1]
                demand = decrypt(encDemand, targetUser.getShared())
                response = encrypt(eval(demand), targetUser.getShared())
                sending += "||ruth||" + response + "||"    
            if("ruth" in newVals):
                encResponse = newVals[newVals.index("ruth") + 1]
                response = decrypt(encResponse, targetUser.getShared())
                if(seen[d2][1] == response):
                    verified.append(userName)
                else:
                    seen[d2][1] = -100.10233
            if("msg" in newVals):
                mailbox[userName].append(">: " + newVals(newVals.index("msg")+1))
                
        else:
            do_one(d2, 1, "you have been banned from speaking to this user")        

        data1 = re.search('@@(.*)', d1)
        datapart = data1.group(0)
    

def keyAgreement(mod, mySecret, userPublic):
    val1 = int(userPublic)
    val2 = int(mySecret)
    val3 = int(mod)
    a = (val1 ** val2) % val3
    print(a)
    return a

def createPublic(mod, base, mySecret):
	return (int(base) ** int(mySecret)) % int(mod)

def encrypt(message, sharedKey):
    key = sharedKey
    while(len(key)<32):
        key = key * 10
    cha = ChaCha(key)
    return cha.encrypt(message)

def decrypt(message, sharedKey):
    key = sharedKey
    while(len(key)<32):
        key = key * 10
    cha = ChaCha(key)
    return cha.decrypt(message)

def authenticate(level):
    request = randint(0,23)
    operations = "*%-+/"
    for i in range(0,level):
        request += operations[randint(0,len(operations))] + randint(0,23)
    expected = eval(request)
    return [request, expected]

verified = []
seen = {}
mailBox = {}
seenMail = {}
knownUsers = {}
myUser = None
outUser = "frank"
def main():
    global mailBox
    global verified
    global seen
    global knownUsers
    global outUser
    global seenMail
    while True:
        toClean = raw_input("command: ")
        command = toClean.strip()
        if(command[:4] == "exit"):
            print("exiting program, bye...")
            break
        elif(command[:5] == "-user"):
            myUser = knownUsers[getpass.getpass("Username: ").strip()]
        elif(command[:6] == "-alias"):
            values = command.split(" ")
            outUser = values[values.index("-alias") + 1]
        elif(command[:5] == "--new"):
            #for optimal security we would calculate a random mod and base that
            #match
            values = command.split(" ")
            userName = values[values.index("-user") + 1]
            random = string_to_int(os.urandom(9999)[:4])
            newUser = User(userName, 23, 5, random, -1)
            if("-gen" in command):
                #create new key for the user
                curve = SECP_256k1()
                privateKey = string_to_int(os.urandom(curve.coord_size))
                privateKey2 = int_to_string(privateKey)
                newUser.setShared(string_to_int(privateKey2[:4]))
            else:
                key = getpass.getpass("Input your private key: ")
                newUser.setShared(key)
            knownUsers[newUser.getName()] = newUser
        elif(command[:3] == "-eU"):
            rest = command[3:].strip()
            tempUser = User(None, -1, -1, -1, -1)
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
            user.setShared(keyAgreement(user.getMod(), myUser.getShared(), user.getPub()))
        elif(command[:5] == "-load"):
            values = command.split(" ")
            fileLoc = values[values.index("-f") + 1]
            newList = pickle.load(open(fileLoc, "r"))
            knownUsers.update(newList)
        elif(command[:5] == "-save"):
            values = command.split(" ")
            fileLoc = values[values.index("-f") + 1]
            pickle.dump(knownUsers, open(fileLoc, "w"))
        elif(command[:4] == "-pub"):
            values = command.split(" ")
            if("-u" in values):
                user = knownUsers[values[values.index("-u") + 1]]
                print(createPublic(user.getMod(), user.getBase(), myUser.getShared()))
            else:
                mod = values[values.index("-mod") + 1]
                base = values[values.index("-base") + 1]
                print(createPublic(mod, base, myUser.getShared()))
        elif(command[:8] == "-connect"):
            values = command.split(" ")
            user = ""
            ip = ""
            if("-new" in values):
                ip = values[values.index("-ip") + 1]
                username = values[values.index("-u") + 1]
                user = knownUsers[username]
                fakeRuth = 23
                encRuth = encrypt(fakeRuth, user.getShared())
                authPair = authenticate(11)
                request = authPair[0]
                seen[ip] = [username, authPair[1]]
                encReq = encrypt(request, user.getShared())
                #INCLUDE AUTHENTICATION ORIGINAL MESSAGE
                sending = "||user||" + outUser + "||auth||"
                sending += encReq + "||ruth||" + encRuth
                do_one(ip, 1, sending) 
            elif("-u" in values):
                user = knownUsers[values[values.index("-u") + 1]]
                for a in seen.keys():
                    if(seen[a][0] == user):
                        ip = a
                        break
            else:
                user = knownUsers[raw_input("Target's username: ")]
                if("-ip" in values):
                    ip = values[values.index("-ip") + 1]
                else:
                    ip = raw_input("Please input IP: ")
            while(len(mailBox[user.getName()]) > 0):
                temp = mailBox[user.getName()].pop(0)
                seenMail[user.getName()].append(temp)
                print(temp)
            while True:
                while(len(mailBox[user.getName()]) > 0):
                    temp = mailBox[user.getName()].pop(0)
                    print(temp)
                    seenMail[user.getName()].append(temp)
                message = raw_input("\n")
                seenMail.append(message)
                enc = encrypt("||msg||" + message, user.getShared())
                do_one(ip, 1, enc)
        elif(command[:5] == "-check"):
            print("User : New Message(s) : Verified")
            for user in mailBox.getKeys():
                if(len(mailBox[user]) > 0):
                    printing = user + " : "
                    if(mailBox[user][-1][:2] == ">:"):
                        printing += "yes : "
                    else:
                        printing += "no : "
                    if(user in verified):
                        printing += "yes"
                    else:
                        printing += "no"
                    print(printing)
        elif(command[:5] == "-help"):
            help = ""
            if("new" in command):
                help += helpNew()
            elif("load" in command.lower()):
                help += helpLoad()
            elif("save" in command.lower()):
                help += helpSave()
            elif("edit" in command.lower()):
                help += helpEdit()
            elif("agree" in command.lower()):
                help += helpAgree()
            elif("all" in command.lower()):
                help += helpAll()
            else:
                help += "--new: creates a new username for you\n"
                help += "-load: loads the list of known users from memory\n"
                help += "-save: saves the list of known users to a file\n"
                help += "-eU: edits an existing user or creates a new one\n"
                help += "-agree: creates key agreement between you and a user\n"
            print(help)
        else:
            print(command + " is not a valid command, please retry or type "+
                    "-help for the list of commands")
main()


