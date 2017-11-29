# Hermod
Cryptography Project 

Hermod (a Secure Communication channel)

by Douglas Mejia & Pedram Namiranian

Named after the Norse messenger to the gods, Hermod is a python terminal-based chat application that allows the users to send secure messages over Ping. Every message is encrypted using Elliptic curve technologies. 


The chat application will allow you to do the following:

Send encryted messages 
Recieve and decrypt messages 
Save known users and their information 
Authenticate users
 

Programs allows users to create a private key and public keys. The program also allows a user to store the public keys of known users. 
All this information will be stored in a Pickle file. The same pickle file will be used to load user information.

User has following options:

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

-The base and mod value for diffie helman

-Its "friends" public key, recieved during key agreement  and shared secret
