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


Running

to create a new user 

	--new -user name [-gen]
		
  -gen is optional and will generate a private key using an elliptic curve 
		omitting will prompt you to enter own private key 


to save new user to a pickle file 
	-save -f [name of file].txt

to log in as loaded user:

	-user
		
  will prompt for username which is name used when user was created

to add new know user to current log in

	-eu -name [user] -mod [mod val] -base [base val] -pub [user pub key] -shared [shared key val]
 	
  example: 
	
    -eU -name paul -mod 13 -base 9 -pub 53 -shared 6
			
  creates new known user paul with public key 53 and shared key 6 etc.

to create alias (to hide name)
	    
     -alias [alias]

To connect and chat with know user"

  first load your files 
 
           -load -f [file]
  sign in
           
           -user 
		             [enter username]
  create alias (optional)
	
            -alias [alias]

  connect to known user 
	 
             -connect -new -u [user you want to connect to] -ip [user ip address] 

	
  once in chat type 'exit' to return to menu. 

	

Example Chatting:

There are two users already created with a shared key and all (mac or frank).

To log into these one these users (mac or frank)
type commands

	-load -f [mac.txt]
		[frank.txt] to load frank

once their info is load signin as user using commands

	-user 
		will ask you for username. which should just be the name used when the user was created
			username: [enter username ]
		in the case of mac, the username is 'mac'.
		for frank, the username is 'frank'

then to connect to a user type

	-connect -new -u [user you want to connect to] -ip [user ip address] 

		this will send you to the 'chat room' if other user is also connect ( gont through aforementioned steps)
		you will be able to send messages to each other.

please note that root access is need for communication to work. 

These steps are the same for other users

Program works between raspberry pi's


