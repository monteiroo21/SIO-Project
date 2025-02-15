import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature

# Geração de chaves ECC e armazenamento protegido
def key_gen(password, credential_file):
    """
    Gera chaves ECC, salva a chave pública e privada protegida por senha.
    """
    if os.path.exists(credential_file):
        return
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    with open(credential_file, 'wb') as f:
        # Salvar chave pública
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Salvar chave privada protegida por senha
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password)
        ))


# Carregar chaves ECC de um ficheiro protegido
def key_load(password, credential_file):
    """
    Carrega a chave privada e deriva a chave pública a partir de um ficheiro protegido.
    """
    with open(credential_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password
        )
        public_key = private_key.public_key()
    return private_key, public_key

# Carregar chave privada de um ficheiro
def load_private_key(password, credential_file):
    """
    Carrega a chave privada de um ficheiro que contém ambas as chaves.
    """
    with open(credential_file, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password
        )
    return private_key

# Carregar chave pública de um ficheiro
from cryptography.hazmat.primitives import serialization

def load_public_key(credential_file):
    """
    Carrega a chave pública de um ficheiro que contém ambas as chaves.
    """
    with open(credential_file, 'rb') as f:
        content = f.read()
    # Extrair a chave pública diretamente
    try:
        public_key = serialization.load_pem_public_key(content)
    except ValueError:
        # Caso contenha tanto chave privada quanto pública, extraímos manualmente a parte da chave pública
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
    with open(credential_file, "r") as file:
        lines = file.readlines()

    # Extrair apenas a chave pública
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


# Encriptação de dados com AES-GCM usando ECC para troca de chaves
def encrypt_data(data, private_key, peer_public_key):
    """
    Encripta dados com AES-GCM usando chaves derivadas de ECC.
    """
    # Derivar um segredo compartilhado
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derivar uma chave simétrica usando HKDF
    salt = os.urandom(16)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"handshake data",
    ).derive(shared_key)

    # Encriptar os dados com AES-GCM
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()

    return ciphertext, nonce, encryptor.tag, salt


# Desencriptação de dados com AES-GCM
def decrypt_data(ciphertext, nonce, tag, salt, private_key, peer_public_key):
    """
    Desencripta dados com AES-GCM usando chaves derivadas de ECC.
    """
    # Derivar o segredo compartilhado
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

    # Derivar a mesma chave simétrica usando HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"handshake data",
    ).derive(shared_key)

    # Desencriptar os dados com AES-GCM
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext


# Assinatura de dados
def sign_data(data, private_key):
    """
    Assina os dados usando a chave privada ECC.
    """
    hashed_message = hashes.Hash(hashes.SHA256())
    hashed_message.update(data)
    digest = hashed_message.finalize()
    signature = private_key.sign(
        digest,
        ec.ECDSA(Prehashed(hashes.SHA256()))
    )
    return signature, digest


# Verificação de assinatura
def verify_signature(signature, digest, public_key):
    """
    Verifica a assinatura usando a chave pública ECC.
    """
    try:
        public_key.verify(
            signature,
            digest,
            ec.ECDSA(Prehashed(hashes.SHA256()))
        )
        print("Assinatura verificada com sucesso!")
        return True
    except InvalidSignature:
        print("Erro: Assinatura inválida!")
        return False


# Teste do fluxo completo
if __name__ == "__main__":
    password = b"minha_senha_segura"
    credential_file_sender = "sender_credentials.pem"
    credential_file_receiver = "receiver_credentials.pem"

    # Gerar chaves para o remetente e destinatário
    key_gen(password, credential_file_sender)
    key_gen(password, credential_file_receiver)

    # Carregar chaves
    sender_private_key = load_private_key(password, credential_file_sender)
    sender_public_key = load_public_key(credential_file_sender)
    receiver_private_key = load_private_key(password, credential_file_receiver)
    receiver_public_key = load_public_key(credential_file_receiver)

    # Dados a serem encriptados
    message = b"Hello, this is a secure message!"

    # Assinar os dados
    signature, digest = sign_data(message, sender_private_key)

    # Encriptação
    ciphertext, nonce, tag, salt = encrypt_data(message, sender_private_key, receiver_public_key)

    print("Mensagem encriptada com sucesso!")

    # Desencriptação
    try:
        plaintext = decrypt_data(ciphertext, nonce, tag, salt, receiver_private_key, sender_public_key)

        # Verificar a assinatura
        if verify_signature(signature, digest, sender_public_key):
            print("Mensagem desencriptada com sucesso:", plaintext.decode())
    except InvalidSignature:
        print("Erro: Assinatura inválida ou os dados foram corrompidos.")
    except Exception as e:
        print(f"Erro ao desencriptar a mensagem: {e}")
