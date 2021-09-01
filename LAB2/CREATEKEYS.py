import os
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


#------------------------------------START OF A FUNCTION------------------------------------------
def generate_store_key_pairs(user,key_len):
    #generating the private key for the user of specified key length 
    private_key = rsa.generate_private_key(public_exponent = 65537,
        key_size = key_len,
        backend = default_backend()
    )
    #generating its corresponding public key
    public_key = private_key.public_key()
    #creating two directories Private and Public if they are not created before
    #the directories are created to store the public and private key of the users
    if not os.path.exists("Private"):
        os.mkdir("Private")
        
    if not os.path.exists("Public"):
        os.mkdir("Public")

    
    #geting the pem format of the private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    #storing the private key at desired location
    cwd = os.getcwd()
    private_key_filename = user + "_" + "priv" + str(key_len) + ".pem"
    path = os.path.join(cwd,"Private",private_key_filename)

    with  open(path,'wb') as f:
        f.write(pem)


    
    public_key_filename = user + "_" + "pub" + str(key_len) + ".pem"
    path = os.path.join(cwd,"Public",public_key_filename)
    #geting the pem format of the public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    #storing the private key at desired location
    with open(path,'wb') as f:
        f.write(pem)

#-----------------------END OF THE FUNCTION-------------------------------------------------------------



#------------------------------------START OF A FUNCTION------------------------------------------
        
def create_keys(user_name_list,RSA_keysize):
    #reads the file
    f = open(user_name_list,'r')
    users = f.readlines()
    f.close()
    #one by one getting the name of the users and generating a rsa key pair
    for user in users:

        generate_store_key_pairs(user.strip(),RSA_keysize)
        print("The key pairs are created successfully for the user {}".format(user.strip()))

    return "SUCESSFULLY CREATED ALL THE KEY PAIRS"

# ----------------------------------END OF THE FUNCTION------------------------------------------------