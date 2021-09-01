import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def get_public_key(user,RSA_keysize):
    cwd = os.getcwd()
    public_key_filename = user + "_" + "pub" + str(RSA_keysize) + ".pem"
    path = os.path.join(cwd,"Public",public_key_filename)

    with open(path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def get_private_key(user,RSA_keysize):
    cwd = os.getcwd()
    private_key_filename = user + "_" + "priv" + str(RSA_keysize) + ".pem"
    path = os.path.join(cwd,"Private",private_key_filename)

    with open(path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key