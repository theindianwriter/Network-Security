import sys
import os
import random
import base64
import socket
import pickle
#cryptographic modules
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as pad



# -----------------------------------------SSHClient Class ------------------------------------------------

class SSHClient:

    #constructo
    def __init__(self,SSH_IP_ADDR,SSH_PORT,client_name):

        self.SSH_IP_ADDR = SSH_IP_ADDR
        self.SSH_PORT = SSH_PORT
        self.client_name = client_name
        #the file which contains information about the users together with there passpharse
        self.usersfilename = "users.txt"
        self.client_Prompt = False
        #default initialization vector
        self.master_iv = b'\xd5\x7f\x95\x8fK/\xa5\x08\x9f\x1c\xb3\x9f\x11(x\xca'

    # ----------------------START OF USER INTERFACE METHOD ----------------------------------------

    def __UserInterface(self):
        #gets input from the user
        while True:
            users_input = input("Client-Prompt> ")
            if len(users_input) > 0:
                break

        #if the input is logout then terminate from the client mode
        if users_input == "logout":
            self.client_Prompt = False

        #encrypting the commands with the help of session key  of the client
        users_input = users_input.encode("ascii")
        
        padder = pad.PKCS7(128).padder()
        padded_users_input = padder.update(users_input) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(self.master_iv),backend=default_backend())
        encryptor = cipher.encryptor() 
        ecrypted_command = encryptor.update(padded_users_input) + encryptor.finalize()
        
        #sending in the form a dictionary
        return {'command': ecrypted_command,"encrypted": "YES"}

    # ---------------------------------end of user interface method -------------------------------
    # ---------------------------------START OF NETWORK INTERFACE METHOD ---------------------------
    def __NetworkInterface(self):
        #creating a socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #initialing connection with the server with this message
        message = {"command": "initiate","encrypted": "NO"}
        #pickling the data to be send in the right format 
        data = pickle.dumps(message)

        print("CONNECTION INITIATED WITH THE SSH SERVER")
        try:
            s.connect((self.SSH_IP_ADDR,self.SSH_PORT))
            print("CONNECTED TO THE SSH SERVER WITH IP ADDRESS "+str(self.SSH_IP_ADDR)+":"+str(self.SSH_PORT))
            s.sendall(data)
            reply = s.recv(1024)
            reply = pickle.loads(reply)
        except:
            print("CONNECTION FAILED!!")
            #status to show that some error has occured
            return 1

        #if all okay then receiving the public key of the ssh server
        output = reply["output"]
        print("Public key of the server received")
        
        #storing the public key of the serve in the client local directory
        if not os.path.exists("SSHClient_"+self.client_name):
            os.mkdir("SSHClient_"+self.client_name)
        
        cwd = os.getcwd()
        server_public_filename = "server_pub.txt"
        path = os.path.join(cwd,"SSHClient_"+self.client_name,server_public_filename)


        with open(path,'wb') as f:
            f.write(output)
        #getting the server public key instance which can be used to encrypt data
        server_public_key = serialization.load_pem_public_key(
            output,
            backend=default_backend()
        )
        #checking for the users   
        f = open(self.usersfilename,'r')
        data = f.readlines()
        f.close()
        #getting the username and the passphrase of the respective client
        username = ''
        userpassphrase = ''
        for user_data in data:

            info = user_data.strip().split(" ")
            username = info[0]
            userpassphrase = info[1]

            if username == self.client_name:
                break

        if username != self.client_name:
            print("PASSPHRASE OF THE USER NOT FOUND")
            return 1
        # -------------------------for authentication with the ssh server ---------------------------
        #generating the session key 
        self.session_key = os.urandom(32)
        #creaing the packet
        packet = username + "###" + userpassphrase + "###" + str(base64.b64encode(self.session_key ),'utf-8')
        packet = packet.encode("ascii")
        #encrypted the packet with the server public key
        encrypted_packet = server_public_key.encrypt(
            packet,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

        message = {"command": "auth","message": encrypted_packet,"encrypted": "NO"}
        data = pickle.dumps(message)
        print("INITIALIATED AUTHENTICATION......")
        try:
            s.sendall(data)
            reply = s.recv(1024)
            reply = pickle.loads(reply)
        except:
            print("ERROR WHILE INITIATING AUTHENTICATIO")
        

        output = reply["output"]
        if output == "OK":
            print("AUCTHENTICATED BY THE SSH SERVER")
            print("SWITCHED TO CLIENT PROMPT")
            self.client_Prompt = True
        else:
            print('ERROR!!!!')
            return 1

        # ------- end of aiuthentication of the client --------------------------------
        # -------- if the authentication done then client prompt will appear and the client can type
        #in the comments
        #all the communication is encrypted
        while self.client_Prompt:

            message = self.__UserInterface()
            data = pickle.dumps(message)
            try:
                s.sendall(data)
                reply = s.recv(1024)
                reply = pickle.loads(reply)
            except:
                print("ERROR WHILE SENDING COMMAND")
                continue
            
            output = reply["output"]
            
            #decrypring the message with the session key
            cipher = Cipher(algorithms.AES(self.session_key), modes.CBC(self.master_iv),backend=default_backend())
            decryptor = cipher.decryptor()
            padded_message = decryptor.update(output) + decryptor.finalize()
            unpadder = pad.PKCS7(128).unpadder()
            message = unpadder.update(padded_message) + unpadder.finalize()
            message = message.decode("ascii")

            if message != 'do not print':
                print(message)

        print("BACK TO THE MAIN PROMPT")
        s.close()
        return 0
# ------------------------------------- end of network interface method ------------------------------------

    #start of the cliennt if ssh then connection opens if exit then terminates the program
    def start(self):

        while not self.client_Prompt:
            print("TYPE ssh FOR CONNECTION WITH SSH SERVER OR exit FOR TERMINATION")
            user_input = input("Main-Prompt> ")
            if user_input == "ssh":
                self.__NetworkInterface()
            elif user_input == "exit":
                break
            else:
                print("wrong input")

# ==============================================END OF SSH CLIENT CLASS ====================================
        
#the client program starts from here        
if __name__ == '__main__':

    #getting the arguments
    arg = sys.argv
    SSH_IP_ADDR = arg[1]
    SSH_PORT = int(arg[2])
    client_name = arg[3]
    #creating an instance of the client
    C = SSHClient(SSH_IP_ADDR,SSH_PORT,client_name)
    #starting the cient 
    C.start()

