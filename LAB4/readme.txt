This is the readme file for assigmnent 4 of Network Security(CS6500).

In this asignment the functionality of an SSH client and an SSH server using the
socket interface and crytographic routines is implemented.There are two major components in 
this assignment the SSH server and the SSH client.

To run this programs this steps should be followed.

Step 1: Create a filename named users.txt(make sure  name of the file is same as it is) in the 	current working directory.In the file write users details in each line with format 
	name passphrase. e.g 
	alice somepassword
	bob someotherpassord
	mahesh someother 
Note: if the file is not created then a default file is created with alice and bob as users.

Step 2: Open a terminal for the ssh server and type and in this format:
	python3 sshserver.py PORT_NO e.g 
	python3 sshserver.py 12345
	
Step 3: Open another terminal for the sshclient and type in this format:
	python3 sshclient.py SERVER_IP_ADDRESS SERVER_PORT_NO NAME e.g
	python3 sshclient 127.0.0.1 12345 alice
	
Step 4: In the ssh client terminal a mainprompt would appear. Type ssh for connection or exit to 		terminate.Type ssh e.g
	ssh
	
Step 5: The user would be authenticated and client prompt would appear.
	Type in your commands.
	listfiles - to list all the directories of the current folder
	cwd - to get the working directory
	chgdir absolutepath - to change the current directory (absolute path should not contain any 
				spaces)
				
	mv filename absolutesourcepaath absolutedestpath - to move the file (the paths should not 								contain any spaces)
	cp filename absolutesourcepaath absolutedestpath - to move the file (the paths should not 								contain any spaces)
	
	e.g listfiles
	e.g cwd
	e.g cp file.txt <src_absolute_path> <dest_absolute_path> 
	e.g chgdir <absoute_path>
	e.g cp file.txt <src_absolute_path> <dest_absolute_path> 
	
Step 6: Type logout to terminate from the client prompt
	e.g logout
	
Step 7: would again return back to the main prompt. type ssh to connect again or exit to terminate
	e.g exit
	
	
ERROR CASES AND WEAKNESSES:

The server must be up before the client is invoked.Also the ipadress and port no of the server should be correct otherwise error would occur.
The arguments mentioned above should be correct and given in  the same order otherwise an error may occur.
The filehandling is not taken care in some of the places.So make sure to not feed wrong input or wrong arguments.
	

