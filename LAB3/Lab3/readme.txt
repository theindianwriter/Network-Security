This is the readme file for the assignment 3 of Network Security(CS6500).

It implements the KDC-based key establishment (exchange) for use with symmetric key encryption algorithms.It has two programs: (a) Key Distribution Center (KDC), and (b) Client(C).

At start of execution, at least 3 Terminal windows, one each for the KDC and two clients need to be 
opened.In the folder a file named "passwd.txt" needs to created to store all the clients password 
by the KDC.Also an input text called "in.txt" needs to be created which contains the content to be 
send by the sender.

The following steps need to be executed in order to see the results.Do more remember to create the 
above mentioned files with appropriate names.

Step 1 : (In 1st terminal for KDC) execute the following command
	python3 kdc.py -p 12345 -o out.txt -f passwd.txt
	
Step 2: (In 3rd terminal for RECEIVER) execute the following command
	python3 client.py -n bob -m R -s outenc.txt -o out.txt -a 127.0.0.1 -p 12345
	
Step 3: (In 2nd terminal for sender) execute the following command
	python3 client.py -n alice -m S -o bob -i in.txt -a 127.0.0.1 -p 12345
	
	
	
The program runs correctly if all the steps are followed in given order.
If the necessary conditions are not provided or if illogical steps are executed then the program 
may halt and throw and exception.Error handling is done in some of the cases but in some cases also 
error handling is not done due to limitation of time.



	
	


 
