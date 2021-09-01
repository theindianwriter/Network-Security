import argparse
import socket
import sys
import pickle
import time
import os
import base64
import random
import string
#cryptography librabries

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as pad


class Client:
    #constructor of the client
    def __init__(self,args):
        self.kdc_ip = args.a
        self.kdc_port = args.p
        self.client_name = args.n
        self.client = args.m
        self.outencfile = args.s
        self.inputfile = args.i
        self.output = args.o
        self.iv = b'\xd5\x7f\x95\x8fK/\xa5\x08\x9f\x1c\xb3\x9f\x11(x\xca'


    def start(self):

        if self.client == 'S':
            self.__sender()
        elif self.client == "R":
            self.__receiver()
        else:
            print("S or R, wrong value")

    #function that registers with the KDC
    def __register(self):

        self.password = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 80))
        self.client_ip_address = '127.0.0.1'
        self.client_port_no = random.randrange(30000,39999,5)
    
        message = {"code": 301,"password" : self.password,"ip_address": self.client_ip_address,"port_number" : self.client_port_no, "name": self.client_name}
        data = pickle.dumps(message)	

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((self.kdc_ip,self.kdc_port))
            
            print("connected to kdc for registration")
            s.sendall(data)
            reply = s.recv(1024)
            reply = pickle.loads(reply)
        finally:
            print("registration done!!!")
            s.close()

    #-------------------------------SENDER --------------------------------------------------------
    #if the client is a sender do appropriate action
    def __sender(self):

        self.__register()
        print("sleeping for 15 seconds")
        time.sleep(15)
        print("end sleeping")

        #sending to the KDC for getting session key
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        digest = hashes.Hash(hashes.MD5(),backend=default_backend())
        digest.update(bytes(self.password,encoding="utf-8"))
        client_key = digest.finalize()

        message = self.client_name + "###" + self.output + "###" + str(os.urandom(32))
        message = message.encode("ascii")

        padder = pad.PKCS7(128).padder()
        padded_message = padder.update(message) + padder.finalize()

        cipher = Cipher(algorithms.AES(client_key), modes.CBC(self.iv),backend=default_backend())
        encryptor = cipher.encryptor() 
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

        data = {"code": 305,"message": encrypted_message,"name": self.client_name}
        data = pickle.dumps(data)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((self.kdc_ip,self.kdc_port))
            print("connected to kdc for getting session key")
            s.sendall(data)
            reply = s.recv(1024)
            reply = pickle.loads(reply)
        finally:
            s.close()


        #after getting the encryped form of the session
        if(reply["code"] == 306):
            encrypted_message = reply["message"]

            cipher = Cipher(algorithms.AES(client_key), modes.CBC(self.iv),backend=default_backend())
            decryptor = cipher.decryptor()
            padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
            unpadder = pad.PKCS7(128).unpadder()
            message = unpadder.update(padded_message) + unpadder.finalize()
            

            divided_messages = message.split(bytes('@@@',"utf-8"))

            message_part_A = divided_messages[0]
            message_part_B = divided_messages[1]

            message_part_A = message_part_A.decode("ascii")

            info = message_part_A.split("###")
            #getting the session key
            session_key = base64.b64decode(bytes(info[0],'utf-8'))
            receiver_name = info[2]
            received_nonce = info[3]
            receiver_ip = info[4]
            receiver_port = int(info[5])
            
            #sending the rest of the message to the receiver 
            data = {"code": 309,"message": message_part_B,"name": self.client_name}
            data = pickle.dumps(data)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((receiver_ip,receiver_port))
                print("connected to receiver at "+str(receiver_ip)+":"+str(receiver_port))
                s.sendall(data)
                reply = s.recv(1024)
                reply = pickle.loads(reply)
            finally:
                s.close()
        #the message to be sent as in the input file is encrpyted and sent to the receiver
        if(reply["code"] == "success"):
            
            f = open(self.inputfile,"r")
            message = f.read()
            f.close()

            message = message.encode("ascii")

            padder = pad.PKCS7(128).padder()
            padded_message = padder.update(message) + padder.finalize()

            cipher = Cipher(algorithms.AES(session_key), modes.CBC(self.iv),backend=default_backend())
            encryptor = cipher.encryptor() 
            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()

            data = {"message": encrypted_message}
            data = pickle.dumps(data)
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((receiver_ip,receiver_port))
                s.sendall(data)
                reply = s.recv(1024)
                reply = pickle.loads(reply)
            finally:
                s.close()
            #quiting after sending the message in encrypted format with the help of session key
            print("quits after sending message to receiver "+receiver_name)


    # -----------------------------------RECEIVER CLIENT -------------------------------
    def __receiver(self):
    
        self.__register()
        #geting the client key 
        digest = hashes.Hash(hashes.MD5(),backend=default_backend())
        digest.update(bytes(self.password,encoding="utf-8"))
        client_key = digest.finalize()

        #Now acting as a server which can receive message from the sender
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        
        try:
            s.bind((self.client_ip_address,self.client_port_no))
        except (socket.error):
            print(socket.error)
            print("bind failed")
            sys.exit()

        s.listen(1)

        conn,addr = s.accept()
        print("connected with the sender") 

        data = conn.recv(2048)
        data = pickle.loads(data) if len(data) > 0 else ""
        sender_name = data["name"]
        encrypted_message = data["message"]
        #received the message from the sender and got the session key
        cipher = Cipher(algorithms.AES(client_key), modes.CBC(self.iv),backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadder = pad.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()

        message = message.decode("ascii")

        info = message.split("###")
        #the session key (by decrypting using its own password) 
        session_key = base64.b64decode(bytes(info[0],'utf-8'))

        received_nonce = info[3]
        sender_ip = info[4]
        sender_port = int(info[5])

        reply = {"code": "success"}
        reply = pickle.dumps(reply)

        conn.sendall(reply)
        conn.close()
        #closing the connection

        conn,addr = s.accept()
        #again connecting and getting the encrypted message (with the sessin key)
        data = conn.recv(2048)

        data = pickle.loads(data) if len(data) > 0 else ""
        print("encypted data received !!! ")
        encrypted_message = data["message"]
        #saving the encrypted message
        f = open(self.outencfile,'wb')
        f.write(encrypted_message)
        f.close()

        #decrypting with the help of the session key 
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(self.iv),backend=default_backend())
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadder = pad.PKCS7(128).unpadder()
        message = unpadder.update(padded_message) + unpadder.finalize()

        message = message.decode("ascii")
        #saving the decrpyted message into the output file
        f = open(self.output,"w")
        f.write(message)
        f.close()

        reply = {"code": "success"}
        reply = pickle.dumps(reply)
        conn.sendall(reply)

        conn.close()
        #closing the connection after succssfully reading the message
        print("successfully read the message from the sender "+sender_name)
        s.close()



if __name__ == '__main__':
    # Create an argument parser
    parser = argparse.ArgumentParser(description="Client")

    # Tunable parameters as external arguments
    parser.add_argument('-n',required=True,help="client name")
    parser.add_argument('-m',required=True,help="S or R ?")
    parser.add_argument('-a',required=True,help="kdc ip address")
    parser.add_argument('-p',required=True,type=int,help="port number")
    parser.add_argument('-i',default="input.txt",help="input file")
    parser.add_argument('-o',required=True,help="recievers name if sender else output file")
    parser.add_argument('-s',default="outenc.txt",help="file to store the contents received by the client")

    # Parse the input arguments
    args = parser.parse_args()
    #creating an instance of the client
    C = Client(args)
    C.start()
