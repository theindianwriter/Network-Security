import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import utils
from helper import get_public_key
from helper import get_private_key


# ----------------------------START OF FUNCTION -------------------------------------------------------
#TAKES ALL THE NECESSARY ARGUMENTS AND CREATE AN ENCRYPTED MAIL TO PROVIDE CONFIDENTIALITY
def conf_create(sender,receiver,email_input_file,email_output_file,digest_algo,encry_alg,RSA_keysize):

    #read message to be sent as a email from the email input file
    f1 = open(email_input_file,"r")
    plaintext = bytes(f1.read(),'ascii')
    f1.close()
    # get the receiver public key to maintain confidentiality
    public_key = get_public_key(receiver,RSA_keysize)

    ciphertext = ""
    encrypted_key = ""
    #AES ENCRYPTION
    if (encry_alg == "aes-256-cbc"):
        #pads the data appropriately so that the data is of the block sizes
        padder = pad.PKCS7(128).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        #generating a random session key
        key = os.urandom(32)
        #fixing the initialization vector of 12 bytes
        iv = b'\xd5\x7f\x95\x8fK/\xa5\x08\x9f\x1c\xb3\x9f\x11(x\xca'
        #encrypting the padded plain text with the help of the session key
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),backend=default_backend())
        encryptor = cipher.encryptor() 
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        #encrypting the session key with the receiver public key
        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    #3DES ENCRYTION
    elif (encry_alg == "des-ede3-cbc"):
        #pads the data appropriately so that the data is of the block sizes
        padder = pad.PKCS7(64).padder()
        padded_plaintext = padder.update(plaintext) + padder.finalize()
        #generating a random session key
        key = os.urandom(24)
        #fixing the initialization vector of 8 bytes
        iv = b'x\xbc\xdf\xea\x1c\xe6\x94B'
        #encrypting the padded plain text with the help of the session key
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv),backend=default_backend())
        encryptor = cipher.encryptor() 
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        #encrypting the session key with the receiver public key
        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    else:
        return "WRONG ENCRYPTION ALGORITHM"

    #wrinting the encryted key and the cipher text
    f2 = open(email_output_file,"wb")
    f2.write(encrypted_key) #writes in the line 1
    f2.write(bytes('###','ascii')) #to distinguish between the encrypted key and the cipher text
    f2.write(ciphertext) #writes in the line
    f2.close()

    return "ENCRYPTED EMAIL MESSAGE SUCCESSFULLY"

#---------------------------END OF FUNCTION ---------------------------------------------------------




# ----------------------------START OF FUNCTION -------------------------------------------------------
#TAKES ALL THE NECESSARY ARGUMENTS AND CREATE AN EMAIL TO PROVIDE AUTHENTICATION
def auin_create(sender,receiver,email_input_file,email_output_file,digest_algo,encry_alg,RSA_keysize):
    
    #read message to be sent as a email from the email input file
    f1 = open(email_input_file,"r")
    plaintext = bytes(f1.read(),'ascii')
    f1.close()

    hash_val = ''
    chosen_hash = ''
    #based on the digest algo hash value will be generated of the plaintext
    if digest_algo == 'sha512':

        chosen_hash = hashes.SHA512()
        digest = hashes.Hash(hashes.SHA512(),backend=default_backend())
        digest.update(plaintext)
        hash_val = digest.finalize()

    elif digest_algo == 'sha3-512':

        chosen_hash = hashes.SHA3_512()
        digest = hashes.Hash(hashes.SHA3_512(),backend=default_backend())
        digest.update(plaintext)
        hash_val = digest.finalize()

    else:
        return "WRONG DIGEST ALGO!!!"

    #gets the private of the sender
    private_key = get_private_key(sender,RSA_keysize)
    #generating a signature which can be used to authenticate the sender
    sig = private_key.sign(
        hash_val,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )
    #writing the signature and the plaintext
    f2 = open(email_output_file,"wb")
    f2.write(sig) #writes in  line 1
    f2.write(bytes('###','ascii'))
    f2.write(plaintext) #writess in second line
    f2.close()

    return "SUCESSFULLY DONE TO BE AUTHENTICATED"

#----------------------------END OF FUNCTION ---------------------------------------------------------


# ----------------------------START OF FUNCTION -------------------------------------------------------
#TAKES ALL THE NECESSARY ARGUMENTS AND CREATE AN ENCRYPTED MAIL TO PROVIDE CONFIDENTIALITY,AUTHENTICATION AND INTIGRITY
def coai_create(sender,receiver,email_input_file,email_output_file,digest_algo,encry_alg,RSA_keysize):
    #reads email ffrom the file
    f1 = open(email_input_file,"r")
    plaintext = bytes(f1.read(),'ascii')
    f1.close()

    hash_val = ''
    chosen_hash = ''
    #based on the digest algo hash value will be generated of the plaintext
    if digest_algo == 'sha512':

        chosen_hash = hashes.SHA512()
        digest = hashes.Hash(hashes.SHA512(),backend=default_backend())
        digest.update(plaintext)
        hash_val = digest.finalize()

    elif digest_algo == 'sha3-512':

        chosen_hash = hashes.SHA3_512()
        digest = hashes.Hash(hashes.SHA3_512(),backend=default_backend())
        digest.update(plaintext)
        hash_val = digest.finalize()

    else:
        return "WRONG DIGEST ALGO!!!"

    #gets the private key of the sender
    private_key = get_private_key(sender,RSA_keysize)
    #generating a signature which can be used to authenticate the sender
    sig = private_key.sign(
        hash_val,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )
    #geting the public of the receiver that can be used for confidentiality
    public_key = get_public_key(receiver,RSA_keysize)

    ciphertext = ""
    encrypted_key = ""


    if (encry_alg == "aes-256-cbc"):

        padder = pad.PKCS7(128).padder()
        padded_sig_plaintext = padder.update(sig)
        padded_sig_plaintext += padder.update(plaintext)
        padded_sig_plaintext += padder.finalize()

        key = os.urandom(32)
        iv = b'\xd5\x7f\x95\x8fK/\xa5\x08\x9f\x1c\xb3\x9f\x11(x\xca'

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),backend=default_backend())
        encryptor = cipher.encryptor() 
        ciphertext = encryptor.update(padded_sig_plaintext) + encryptor.finalize()

        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

    elif (encry_alg == "des-ede3-cbc"):

        padder = pad.PKCS7(64).padder()
        padded_sig_plaintext = padder.update(sig)
        padded_sig_plaintext += padder.update(plaintext)
        padded_sig_plaintext += padder.finalize()

        key = os.urandom(24)
        iv = b'x\xbc\xdf\xea\x1c\xe6\x94B'

        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv),backend=default_backend())
        encryptor = cipher.encryptor() 
        ciphertext = encryptor.update(padded_sig_plaintext) + encryptor.finalize()

        encrypted_key = public_key.encrypt(
            key,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )
    else:
        return "WRONG ENCRYPTION ALGORITHM"


    f2 = open(email_output_file,"wb")
    f2.write(encrypted_key)
    f2.write(bytes('###','ascii'))
    f2.write(ciphertext)
    f2.close()

    return "ENCRYPTED EMAIL MESSAGE SUCCESSFULLY AUTHENTICATION TO BE DONE"

#-------------------------------------------END OF THE FUNCTION-------------------------------------------

# ----------------------------START OF FUNCTION -------------------------------------------------------

def create_mail(sec_type,sender,receiver,email_input_file,email_output_file,digest_algo,encry_alg,RSA_keysize):
    #based on the security type mail is handled
    if sec_type == "CONF":

        return conf_create(sender,receiver,email_input_file,email_output_file,digest_algo,encry_alg,RSA_keysize)

    elif sec_type == "AUIN":

        return auin_create(sender,receiver,email_input_file,email_output_file,digest_algo,encry_alg,RSA_keysize)

    elif sec_type == 'COAI':

        return coai_create(sender,receiver,email_input_file,email_output_file,digest_algo,encry_alg,RSA_keysize)

    else:
        return "ERROR!!!"

#---------------------------------------------------END OF THE FUNCTON----------------------------------------------