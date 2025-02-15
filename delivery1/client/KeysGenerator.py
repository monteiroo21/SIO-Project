import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

def key_gen(password, credential_file):
    if os.path.exists(credential_file):
        return
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    with open(credential_file, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        ))

def key_gen_without_file():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    return private_key,public_key

def key_load(password, credential_file):
    with open(credential_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password
        )
        public_key = private_key.public_key()
    return private_key, public_key

def load_private_key(password, credential_file):
    with open(credential_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password
        )
    return private_key

def load_private_key_from_bytes(private_key_bytes):

    private_key = serialization.load_pem_private_key(
        private_key_bytes,
        password=None)
    
    return private_key

from cryptography.hazmat.primitives import serialization

def load_public_key(credential_file):
    with open(credential_file, 'rb') as f:
        content = f.read()

    try:
        public_key = serialization.load_pem_public_key(content)
    except ValueError:
        public_key_lines = []
        inside_public_key = False
        for line in content.decode().splitlines():
            if "-----BEGIN PUBLIC KEY-----" in line:
                inside_public_key = True
            if inside_public_key:
                public_key_lines.append(line)
            if "-----END PUBLIC KEY-----" in line:
                break
        public_key_pem = "\n".join(public_key_lines)
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
    
    return public_key


def load_public_key_text(credential_file):
    if credential_file is None or not os.path.exists(credential_file):
        print(f"Error: Credential file '{credential_file}' not found.")
        return None

    with open(credential_file, "r") as file:
        lines = file.readlines()

    public_key_lines = []
    inside_public_key = False
    for line in lines:
        if "-----BEGIN PUBLIC KEY-----" in line:
            inside_public_key = True
        if inside_public_key:
            public_key_lines.append(line)
        if "-----END PUBLIC KEY-----" in line:
            break

    return "".join(public_key_lines)


def encrypt_data(data, private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    salt = os.urandom(16)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"handshake data",
    ).derive(shared_key)

    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, nonce, encryptor.tag, salt


def decrypt_data(ciphertext, nonce, tag, salt, private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"handshake data",
    ).derive(shared_key)

    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

def sign_data(data, private_key):
    hashed_message = hashes.Hash(hashes.SHA256())
    hashed_message.update(data)
    digest = hashed_message.finalize()
    signature = private_key.sign(
        digest,
        ec.ECDSA(Prehashed(hashes.SHA256()))
    )
    return signature, digest


def verify_signature(signature, digest, public_key):
    try:
        public_key.verify(
            signature,
            digest,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        return True
    except InvalidSignature:
        print("Error in Signature")
        return False
