This is the readme file for the Assignment 5 of Network Security (CS6500).

In this algorithm simple firewall rule matching algorithm is implemented.The match is done on a
a set of 6 fields, including source IP address, destination IP address, source port, destination port, protocol, and payload data.

The rule file consists of a set of records, where each record spans multiple lines, in the format given below:

BEGIN
NUM: <<integer>>
SRC IP ADDR: <<a.b.c.d/w>>
DEST IP ADDR: <<j.k.l.m/w>>
SRC PORT: <<integer1>>-<<integer2>>
DEST PORT: <<integer3>>-<<integer4>>
PROTOCOL: tcp | udp | icmp
DATA: <<string>>
END

The packet file  consists of a set of records, where each record spans multiple lines, in the format given below:
BEGIN
NUM: <<integer>>
SRC IP ADDR: r.s.t.u
DEST IP ADDR: j.k.l.m
SRC PORT: <<integer>>
DEST PORT: <<integer>>
PROTOCOL: tcp | udp | icmp
DATA: <<string>>
END

The assignment contains three python3 file namely main.py,ruleparser.py and pktparser.py
In order to test the programs following steps need to be followed:

1) Create two file namely pkt.txt and rule.txt which contains the packets and rules respectively
   in the above specified format.There can be any number of rules as well as packets.Save the file 
   the same folder as the three python files.
2) Open a terminal and execute : python3 main.py rule.txt pkt.txt
3) The results would be displayed in the terminal.


Weakness - The packet and rules format should be as given above and the required arguments with 	appropriate filenames must be present or else some errors may appear.Error handling in some 
	of the cases may appear if the format or some arguments are missing.


