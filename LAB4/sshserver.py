import sys
import os
import random
import base64
import socket
import pickle
import shutil
from _thread import *
#cryptograhic modules
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as pad



# -------------------------------START OF SSH SERVER -------------------------------
class SSHServer:

    #constructor 
    def __init__(self,PORT):

        self.PORT = PORT
        self.ip = ''
        #this file contains information of all the users together with there passphrase
        self.usersfilename = "users.txt"
        self.masterkey = os.urandom(16)
        #this is where session key of different client would be stored
        self.sessions_key = {}
        #the default initialization vector
        self.master_iv =  b'\xd5\x7f\x95\x8fK/\xa5\x08\x9f\x1c\xb3\x9f\x11(x\xca'
        self.initial_directory = os.getcwd()

    def __setup(self):
        # --- generation of private and public keys and there storage at respective locations ---------
        #generating the private keys of the server
        private_key = rsa.generate_private_key(public_exponent = 65537,
        key_size = 2048,
        backend = default_backend()
        )
        #generating the corresponding public key of the server
        public_key = private_key.public_key()
        if not os.path.exists("serverkeys"):
            os.mkdir("serverkeys")
        #creating pem format of the private key
        pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )

        cwd = os.getcwd()
        private_key_filename = "serverpriv.pem"
        path = os.path.join(cwd,"serverkeys",private_key_filename)
        #storing the private key of the server
        with  open(path,'wb') as f:
            f.write(pem)



        public_key_filename = "serverpub.pem"
        path = os.path.join(cwd,"serverkeys",public_key_filename)
        #geting the pem format of the public key
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        #storing the private key at desired location of the server
        with open(path,'wb') as f:
            f.write(pem)
        # ---------------------------------------------------------------------------------------------------
        if not os.path.exists(os.path.join(os.getcwd(),self.usersfilename)):
            data = "alice somepassphrase\nbob someotherpassword\n"
            f = open(self.usersfilename,"w")
            f.write(data)
            f.close()

        f = open(self.usersfilename,'r')
        data = f.readlines()
        f.close()
        
        #for every user creating the key of 128 bit with the help of passpharase and storing in respective files
        for user_data in data:

            info = user_data.strip().split(" ")
            username = info[0]
            userpassphrase = info[1]
            password = bytes(userpassphrase,encoding="utf-8")
        

            digest = hashes.Hash(hashes.MD5(),backend=default_backend())
            digest.update(password)
            client_key = digest.finalize()

            
            #creting a salt of 8 bytes
            salt = os.urandom(8)
            
            

            #appending zeros to salt and creating iv
            iv = salt + bytes('00000000','utf-8')

            cipher = Cipher(algorithms.AES(self.masterkey), modes.CBC(iv),backend=default_backend())
            encryptor = cipher.encryptor() 
            encrypted_client_key = encryptor.update(client_key) + encryptor.finalize()

            if not os.path.exists("UserCredentials"):
                os.mkdir("UserCredentials")

            cwd = os.getcwd()
            filename = username+".txt"
            path = os.path.join(cwd,"UserCredentials",filename)
            Lines = username + '\n' + str(base64.b64encode(encrypted_client_key),'utf-8') + '\n' + \
                                             str(base64.b64encode(iv),'utf-8') +'\n'

            f = open(path,'w')
            f.writelines(Lines)
            f.close()

    # ------------------------START OF COMMAND INTERFACE -----------------------------------

    def __CommandInterface(self,data,addr):
        encrypted = data["encrypted"]
        #if the message is encrypted then decryption need to have and for that appropriate session key is
        #taken
        if encrypted == "YES":
            encrypted_message = data["command"]
            if addr[0]+str(addr[1]) in self.sessions_key.keys():
                session_key = self.sessions_key[addr[0]+str(addr[1])]

                cipher = Cipher(algorithms.AES(session_key), modes.CBC(self.master_iv),backend=default_backend())
                decryptor = cipher.decryptor()
                padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
                unpadder = pad.PKCS7(128).unpadder()
                message = unpadder.update(padded_message) + unpadder.finalize()
                message = message.decode("ascii")
                message = message.split(' ')
                command = message[0]
            else:
                return {"output": "FIRST AUTHENTICATE YOURSELF"},False
                 
        else:
            command = data["command"]
        #--------------------for initialiting the establishment of SSH--------------------------------
        
        if command == "initiate":

            cwd = os.getcwd()
            public_key_filename = "serverpub.pem"
            path = os.path.join(cwd,"serverkeys",public_key_filename)

            with open(path, "rb") as f:
                public_key =  f.read()

            return {"output": public_key},True
        #---------------------------------------------------------------------------------------------
        #---------------------------for authentication of the client ---------------------------------
        elif command == 'auth':

            encrypted_message = data["message"]
            cwd = os.getcwd()
            private_key_filename = "serverpriv.pem"
            path = os.path.join(cwd,"serverkeys",private_key_filename)
            #loading the private key
            with open(path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
            #decrypting using private key of the server
            message = private_key.decrypt(
                encrypted_message,
                padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
                )

            )
            #getting all the info 
            message = message.decode('ascii')
            message = message.split("###")
            username = message[0]
            passphrase = message[1]
            session_key = base64.b64decode(bytes(message[2],'utf-8'))

            password = bytes(passphrase,encoding="utf-8")

            digest = hashes.Hash(hashes.MD5(),backend=default_backend())
            digest.update(password)
            key_got = digest.finalize()

            filename = username + '.txt'
            path = os.path.join(cwd,'UserCredentials',filename)

            f = open(path,'r')
            Lines = f.readlines()
            f.close()
            #orignal client key
            encrypted_client_key = base64.b64decode(bytes(Lines[1].strip(),"utf-8"))
            iv = base64.b64decode(bytes(Lines[2].strip(),'utf-8'))

            cipher = Cipher(algorithms.AES(self.masterkey), modes.CBC(iv),backend=default_backend())
            decryptor = cipher.decryptor()
            client_key = decryptor.update(encrypted_client_key) + decryptor.finalize()

            #if the keys match then authenticated
            #matching the keys
            if key_got == client_key:
                self.sessions_key[addr[0]+str(addr[1])] = session_key
                return {"output": "OK"},True
            else:
                return {"output": "NOK"},True

        #  ----------------------------------------------------------------------------
        #for various commands doing appropriate things
        elif command == 'listfiles':
            try:
                result = os.listdir()
                result = " ".join(result)
            except:
                result = "error"

        elif command == 'cwd':

            try: 
                result = os.getcwd()
            except:
                result = "ERROR!!! "
        
        elif command == 'chgdir':
            try:
                path = message[1]
                os.chdir(path)
                result ="do not print"
            except:
                result = "ERROR!!!"


        elif command == 'cp':
            
            
            try:
                filename = message[1]
                src = message[2]
                dest = message[3]
                shutil.copy(os.path.join(src,filename),dest)
                result = "do not print"
            except :
                result = "ERROR!!!"

        elif command == "mv":
            try:
                filename = message[1]
                src = message[2]
                dest = message[3]
                shutil.move(os.path.join(src,filename),dest)
                result = "do not print"
            except : 
                result = "ERROR!!!"

        elif command == "logout":
            result = "LOGGED OUT"
            
        else:
            result = "COMMAND NOT FOUND"
        
        #encrypting the results

        result = result.encode("ascii")
        padder = pad.PKCS7(128).padder()
        padded_result= padder.update(result) + padder.finalize()
        
        cipher = Cipher(algorithms.AES(session_key), modes.CBC(self.master_iv),backend=default_backend())
        encryptor = cipher.encryptor() 
        ecrypted_result = encryptor.update(padded_result) + encryptor.finalize()

        if command == 'logout':
            del self.sessions_key[addr[0]+str(addr[1])]
            status = False
        else:
            status = True
        #status tells the server either to close connection or not
        return {"output": ecrypted_result},status

# --------------------------------------------end of commmand interface --------------------------
# -------------------------------------------cleint thread --------------------------------------------
    def __clientthread(self,conn,addr):
        
        print("CONNECTED "+str(addr[0])+":"+str(addr[1]))
        while True:
            data = conn.recv(2048)
            data = pickle.loads(data) if len(data) > 0 else ""
            if data == '':
                continue
            message,status = self.__CommandInterface(data,addr)
            if not status:

                reply = pickle.dumps(message)
                conn.sendall(reply)
                break

            reply = pickle.dumps(message)
            conn.sendall(reply)

        os.chdir(self.initial_directory)
        print("CONNECTION CLOSED FROM "+str(addr[0])+":"+str(addr[1]))
        conn.close()   
# ------------------------------------------------end of client thread ---------------------------
# -----------------------------------start of network inerface -------------------------------------

    def __NetworkInterface(self):

        HOST = ''
        PORT = self.PORT
        #setting up the server and listening to the port 
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        print("SOCKET CONNECTED WITH IPV4 OVER TCP")

        try:
            s.bind((HOST,PORT))
        except (socket.error):
            print("BIND FAILED")
            sys.exit()

        print("BIND COMPLETED "+"127.0.0.1"+":"+str(PORT))

        s.listen(4)
        print("LISTENING AT "+"127.0.0.1"+":"+str(PORT))

        while True:

            conn,addr = s.accept()
            start_new_thread(self.__clientthread ,(conn,addr))

        s.close()
# --------------------------------end of network interface -----------------------
    def start(self):
        #first some set up needs to be done
        self.__setup()

        self.__NetworkInterface()
# ------------------------------------------END OF SSH SERVER CLASS -----------------------------------

#this is from where the program starts
if __name__ == '__main__':
    #getting the arguments
    arg = sys.argv

    PORT  = int(arg[1])
    #creaing an instance of the server and starting it
    s = SSHServer(PORT)
    s.start()