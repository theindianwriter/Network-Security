This is a readme file for the assignment 2 of the course Network Security(CS6500)

The project implements the various components of a security-enhanced EMAIL system
similar to PGP (Pretty Good Privacy) and GnuPG which is based on the OpenPGP standard.

Programming language used: Python3

Libraries used : cryptography (pip3 install cryptography)
 
Step 1 : create a file named usernames.txt which contains names of the users in  seperate lines

Step 2 : create  email_input.txt which contains the content of the email.

Step 3 : python3 main.py CreateKeys "usernames.txt" keylen (can be 1024 or 2048)

	e.g python3 main.py CreateKeys "usernames.txt" 1024
	
Step 4 : python3 main.py CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg 		EncryAlg RSAKey-size

	SecType: CONF, AUIN, COAI are three possible string values for the three cases listed 	earlier.
	Sender/Receiver are sender and recipient of this message.
	EmailInputFile contains the input plain-text file (in ASCII format)
	EmailOutputFile contains the output of the encryption algorithms (in binary format)
	DigestAlg is one of: sha512, sha3-512
	EncryAlg is one of: des-ede3-cbc, aes-256-cbc

	e.g python3  main.py CreateMail COAI  alice  bob email_input.txt email_output.txt sha3-512  		aes-256-cbc 1024
	
Step 5 :python3 main.py ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile 		DigestAlg EncryAlg RSAKey-size


	e.g python3  main.py ReadMail COAI  alice bob  email_output.txt plain_ouput.txt sha3-512  		aes-256-cbc 1024


############################ a test example ##############################################
usernames.txt contain the name of users
email_input.txt contains the message of the email. (Do create this two files)

1) python3 main.py CreateKeys "usernames.txt" 1024
2) python3  main.py CreateMail COAI  alice  bob email_input.txt email_output.txt sha3-512  aes-256-cbc 1024
3) python3  main.py ReadMail COAI  alice bob  email_output.txt plain_ouput.txt sha3-512  aes-256-cbc 1024
4) python3  main.py CreateMail COAI  alice  bob email_input.txt email_output.txt sha3-512  aes-256-cbc 1024
5) python3 main.py CreateKeys "usernames.txt" 1024
6) python3  main.py CreateMail COAI  alice  bob email_input.txt email_output.txt sha3-512  aes-256-cbc 1024
7) python3  main.py ReadMail COAI  alice bob  email_output.txt plain_ouput.txt sha3-512  aes-256-cbc 1024
8) python3  main.py CreateMail CONF  alice  bob email_input.txt email_output.txt sha3-512  aes-256-cbc 1024
9) python3  main.py ReadMail CONF  alice bob  email_output.txt plain_ouput.txt sha3-512  aes-256-cbc 1024
10) python3  main.py CreateMail AUIN  alice  bob email_input.txt email_output.txt sha3-512  aes-256-cbc 1024
11) python3  main.py ReadMail AUIN  alice bob  email_output.txt plain_ouput.txt sha3-512  aes-256-cbc 1024
12) python3 main.py CreateKeys "usernames.txt" 2048
13) python3  main.py CreateMail AUIN  alice  bob email_input.txt email_output.txt sha512  des-ede3-cbc 2048
14) python3  main.py ReadMail AUIN  alice bob  email_output.txt plain_ouput.txt sha512  aes-256-cbc 2048
15) python3  main.py CreateMail COAI  alice  bob email_input.txt email_output.txt sha512  des-ede3-cbc 2048
16) python3  main.py ReadMail COAI  alice bob  email_output.txt plain_ouput.txt sha512  des-ede3-cbc 2048
	
	
File handling errors: If the usernames file or email input file is not created then the program 	would throw file handling errors.


Program errors : if the list of arguments is not given or is not given in correct order or wrong 
	argument values are given then the program would give errors or would not run.
	
	
Logic errors : The key pair should be created of a user before creating emails otherwise the program would give errors.The email would be created before reading email and also the arguments used for creating email and reading emails should be same i.e hash algorithm,encrpytion algorihtm,receiver,sender value should be same or the program would send errors. 
	
	




