import argparse
import socket
import sys
import pickle
import os
import base64
from _thread import *
#cryptography librabries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as pad



class Server:

    def __init__(self,portid,outfilename,pwdfile):

        self.portid = portid
        self.outfilename = outfilename
        self.pwdfile = pwdfile
        self.masterkey = os.urandom(16) #to encrypt all the passwords
        self.iv = b'\xd5\x7f\x95\x8fK/\xa5\x08\x9f\x1c\xb3\x9f\x11(x\xca'

    def start(self):

        HOST = ''
        PORT = self.portid

        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        print("socket created with ipv4 address over TCP")

        try:
            s.bind((HOST,PORT))
        except (socket.error):
            print("bind failed")
            sys.exit()

        print("bind completed at "+"127.0.0.1"+":"+str(PORT))

        s.listen(4)

        while True:

            conn,addr = s.accept()
            start_new_thread(self.__clientthread ,(conn,addr))

        s.close()

    def __clientthread(self,conn,addr):

        print("connected to "+str(addr[0])+":"+str(addr[1]))
        while True:
            data = conn.recv(2048)
            data = pickle.loads(data) if len(data) > 0 else ""
            if not data:
                break
            message = self.__create_reply(data,addr)
            reply = pickle.dumps(message)
            conn.sendall(reply)
        print("connection closed to "+str(addr[0])+":"+str(addr[1]))
        conn.close()
    
    def __create_reply(self,data,addr):

        log = "KDC was called by with this code --"+ str(data['code'])+'\n'
        f = open(self.outfilename,"a")
        f.write(log)
        f.close()

        code = data["code"]

        # ----------------------FOR CODE 301 ----------------------------------------------------
        if code == 301:
            #storing all the data received from the client
            name = data["name"]
            password = bytes(data["password"],encoding="utf-8")
            ip_address = data["ip_address"]
            port_no = data["port_number" ]

            #from password of 12 bytes converting to 128 bit key
            digest = hashes.Hash(hashes.MD5(),backend=default_backend())
            digest.update(password)
            client_key = digest.finalize()

            #encypting the key with the master key of the kdc
            cipher = Cipher(algorithms.AES(self.masterkey), modes.CBC(self.iv),backend=default_backend())
            encryptor = cipher.encryptor() 
            encrypted_client_key = encryptor.update(client_key) + encryptor.finalize()
            #the new entry
            new_entry = ":"+name+":"+str(ip_address)+":"+str(port_no)+":"+str(base64.b64encode(encrypted_client_key),'utf-8')+'\n'

            f = open(self.pwdfile,'r')
            Lines = f.readlines()
            f.close()
            #if there exists a client with same name before then overwrite else append
            found = False
            N = len(Lines)
            for i in range(N):
                line = Lines[i]
                words = line.split(":")
                if words[1] == name:
                    Lines[i] = new_entry
                    found = True
                    break
            if not found:
                Lines.append(new_entry)

            f = open(self.pwdfile,'w')
            f.writelines(Lines)
            f.close()
            #sending the reply
            return {"code": 302,"name": name}

        # ------------------------FOR CODE 305 -----------------------------------
        #based on the code do the appropriate as mentioned in the activity of the KDC
        elif code == 305:

            name = data["name"]
            encrypted_message = data["message"]

            f = open(self.pwdfile,'r')
            Lines = f.readlines()
            f.close()
            sender_info = ""
            found = False
            N = len(Lines)
            for i in range(N):
                line = Lines[i]
                words = line.split(":")
                if words[1] == name:
                    sender_info = line.strip()
                    found = True
                    break
            if not found:
                #sending the error code
                return {"code": 404}
            #storing the sender information
            info = sender_info.split(":")
            encrypted_sender_key = base64.b64decode(bytes(info[4],'utf-8'))

            sender_name = info[1]
            sender_ip = info[2]
            sender_port = info[3]


            #getting the sender personal key in non encrypted form 

            cipher = Cipher(algorithms.AES(self.masterkey), modes.CBC(self.iv),backend=default_backend())
            decryptor = cipher.decryptor()
            sender_key = decryptor.update(encrypted_sender_key) + decryptor.finalize()

            #decrpting using sender personal key 
            cipher = Cipher(algorithms.AES(sender_key), modes.CBC(self.iv),backend=default_backend())
            decryptor = cipher.decryptor()
            padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
            unpadder = pad.PKCS7(128).unpadder()
            message = unpadder.update(padded_message) + unpadder.finalize()
            
            message = message.decode('ascii')
            message = message.split("###")

            #getting all the receiver information
            receiver_name = message[1]
            nonce = message[2]
            if sender_name != message[0]:
                return {"code" : 404}

            
            f = open(self.pwdfile,'r')
            Lines = f.readlines()
            f.close()
            receiver_info = ""
            found = False
            N = len(Lines)
            for i in range(N):
                line = Lines[i]
                words = line.split(":")
                if words[1] == receiver_name:
                    receiver_info = line.strip()
                    found = True
                    break
            if not found:
                return {"code": 404}
            
            info = receiver_info.split(":")
            encrypted_receiver_key = base64.b64decode(bytes(info[4],'utf-8'))
            receiver_name = info[1]
            receiver_ip = info[2]
            receiver_port = info[3]
            #generating the session key
            session_key = os.urandom(16)
            # getting the receiver key in unencrypted form
            cipher = Cipher(algorithms.AES(self.masterkey), modes.CBC(self.iv),backend=default_backend())
            decryptor = cipher.decryptor()
            receiver_key = decryptor.update(encrypted_receiver_key) + decryptor.finalize()
            
            #as mentioned in the KDC preparing the message to be sent to the sender
            message_part_A =  str(base64.b64encode(session_key),'utf-8') + "###" + sender_name + "###" +receiver_name +"###" + nonce + "###" + receiver_ip +"###" + receiver_port
            message_part_A = message_part_A.encode("ascii")
            message_part_B = str(base64.b64encode(session_key),'utf-8') + "###" + sender_name + "###" +receiver_name +"###" + nonce +"###" + sender_ip +"###" + sender_port +"###"
            message_part_B = message_part_B.encode("ascii")

            padder = pad.PKCS7(128).padder()
            padded_message_part_B = padder.update(message_part_B) + padder.finalize()

            cipher = Cipher(algorithms.AES(receiver_key), modes.CBC(self.iv),backend=default_backend())
            encryptor = cipher.encryptor() 
            encrypted_message_part_B = encryptor.update(padded_message_part_B) + encryptor.finalize()

            final_message = message_part_A + bytes('@@@',"utf-8")+ encrypted_message_part_B

            padder = pad.PKCS7(128).padder()
            padded_final_message = padder.update(final_message) + padder.finalize()

            cipher = Cipher(algorithms.AES(sender_key), modes.CBC(self.iv),backend=default_backend())
            encryptor = cipher.encryptor() 
            encrypted_final_message = encryptor.update(padded_final_message) + encryptor.finalize()
            
            return {"code" : 306,"message" : encrypted_final_message}
        else:
            return {"code" : 404}



if __name__ == '__main__':
    # Create an argument parser
    parser = argparse.ArgumentParser(description="key distriution center")

    # Tunable parameters as external arguments
    parser.add_argument('-p',default=12345,type=int,help="port number")
    parser.add_argument('-o',default="out.txt",help="output file name")
    parser.add_argument('-f',default="pswd.txt",help="password file name")

    # Parse the input arguments
    args = parser.parse_args()

    #calling the server 
    S = Server(args.p,args.o,args.f)
    S.start()