
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding as pad
from cryptography.hazmat.primitives.asymmetric import utils
from helper import get_private_key
from helper import get_public_key

#------------------------------------START OF A FUNCTION------------------------------------------
def conf_read(sender,receiver,secure_input_file,plain_output_file,digest_algo,encry_alg,RSA_keysize):

    #read message to be sent as a email from the email input file
    f1 = open(secure_input_file,"rb")
    lines = f1.read()
    f1.close()
    lines = lines.split(bytes('###','ascii'))
    #gets the encrypted key and the cipher text
    encrypted_key,ciphertext = lines[0],lines[1]
    #gets the private key of the receiver
    private_key = get_private_key(receiver,RSA_keysize)

    plaintext = ""
    #get the session key by decrypting with the private key
    key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
        )
    )

    if (encry_alg == "aes-256-cbc"):

        iv = b'\xd5\x7f\x95\x8fK/\xa5\x08\x9f\x1c\xb3\x9f\x11(x\xca'
    
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = pad.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()


    elif (encry_alg == "des-ede3-cbc"):

        iv = b'x\xbc\xdf\xea\x1c\xe6\x94B'
    
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv),backend=default_backend())
        decryptor = cipher.decryptor() 
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = pad.PKCS7(64).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    else:
        return "ERROR!!!"


    f2 = open(plain_output_file,"wb")
    f2.write(plaintext)
    f2.close()

    return "READING EMAIL MESSAGE SUCCESSFULL"

#-----------------------END OF THE FUNCTION-------------------------------------------------------------

#------------------------------------START OF A FUNCTION------------------------------------------
def auin_read(sender,receiver,secure_input_file,plain_output_file,digest_algo,encry_alg,RSA_keysize):


    f1 = open(secure_input_file,"rb")
    lines = f1.read()
    f1.close()
    lines = lines.split(bytes('###','ascii'))

    sig,plaintext = lines[0],lines[1]

    hash_val = ''
    chosen_hash = ''

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

    public_key = get_public_key(sender,RSA_keysize)

    public_key.verify(
        sig,
        hash_val,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )

    return "SUCCESSFULLY AUTHENTICATED!!!"

#-----------------------END OF THE FUNCTION-------------------------------------------------------------

#------------------------------------START OF A FUNCTION------------------------------------------
def coai_read(sender,receiver,secure_input_file,plain_output_file,digest_algo,encry_alg,RSA_keysize):
    
    f1 = open(secure_input_file,"rb")
    lines = f1.read()
    f1.close()
    lines = lines.split(bytes('###','ascii'))

    encrypted_key,ciphertext = lines[0],lines[1]

    private_key = get_private_key(receiver,RSA_keysize)

    key = private_key.decrypt(
            encrypted_key,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
            )
        )

    sig_n_plaintext = ""

    if (encry_alg == "aes-256-cbc"):
    
        iv = b'\xd5\x7f\x95\x8fK/\xa5\x08\x9f\x1c\xb3\x9f\x11(x\xca'
    
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv),backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = pad.PKCS7(128).unpadder()
        sig_n_plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()


    elif (encry_alg == "des-ede3-cbc"):
    
        iv = b'x\xbc\xdf\xea\x1c\xe6\x94B'
    
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv),backend=default_backend())
        decryptor = cipher.decryptor() 
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = pad.PKCS7(64).unpadder()
        sig_n_plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    else:
        return "WRONG DECRYPTION ALGORITHM!!!"

    
    plaintext = ''
    sig = ''
    if RSA_keysize == 2048:
        sig = sig_n_plaintext[:256]
        plaintext = sig_n_plaintext[256:]
    elif RSA_keysize == 1024:
        sig = sig_n_plaintext[:128]
        plaintext = sig_n_plaintext[128:]


    chosen_hash = ''
    hash_val = ''

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

    public_key = get_public_key(sender,RSA_keysize)

    public_key.verify(
        sig,
        hash_val,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )
    
    f2 = open(plain_output_file,"wb")
    f2.write(plaintext)
    f2.close()

    return "READ EMAIL SUCCESSFULLY AND AUTHENTICATED"

#-----------------------END OF THE FUNCTION-------------------------------------------------------------
    



#------------------------------------START OF A FUNCTION------------------------------------------
def read_mail(sec_type,sender,receiver,secure_input_file,plain_output_file,digest_algo,encry_alg,RSA_keysize):
    if sec_type == "CONF":

       return  conf_read(sender,receiver,secure_input_file,plain_output_file,digest_algo,encry_alg,RSA_keysize)

    elif sec_type == "AUIN":

        return auin_read(sender,receiver,secure_input_file,plain_output_file,digest_algo,encry_alg,RSA_keysize)

    elif sec_type == 'COAI':

       return coai_read(sender,receiver,secure_input_file,plain_output_file,digest_algo,encry_alg,RSA_keysize)

    else:
        return "ERROR!!!"

#-----------------------END OF THE FUNCTION-------------------------------------------------------------