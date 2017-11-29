# Hermod
Cryptography Project 

Name: Hermod (a Secure Communication channel)

Team: Douglas Mejia & Pedram Namiranian

Project Goal: 

Create a chat application that sends encrypted message through ping(ICMP) that runs on the terminal using Elliptic Curve Encryption 


The Chat application will do the following:

Send encryted messages 
Recieve and decrypt messages 
Save known users and their information 
Authenticate users
 
 
Current Design:

Programs allows users to create a private key and public keys. The program also allows a user to store the public keys of known users. 
All this information will be stored in a Pickle file. The same pickle file will be used to load user information.

Then user has following options:

-new    : update/create private key 

-eU     : new users  and update existing users 

-agree  : key exhange between users

-save   : save known users  

-load   : load known users 

-convos : view ongoing messages 

-enter [username] : enter conversation with certain user and be able to send them messages

-exit   : exits conversation

-quit   : save all information to pickle file. 


Every user has: 
a private key (4 digits)
a list of known users:
	which contains:
		The base and mod value for diffie helman
		Its "friends" public key, recieved during key agreement  and shared secret
