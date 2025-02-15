import os
import sys
import argparse
import logging
import json
import secrets
import requests
import datetime
from KeysGenerator import *
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


logging.basicConfig(format='%(levelname)s\t- %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def load_state():
    state = {}
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    logger.debug('State folder: ' + state_dir)
    logger.debug('State file: ' + state_file)

    if os.path.exists(state_file):
        logger.debug('Loading state')
        with open(state_file,'r') as f:
            state = json.loads(f.read())

    if state is None:
        state = {}

    return state


def parse_env(state):
    if 'REP_ADDRESS' in os.environ:
        state['REP_ADDRESS'] = os.getenv('REP_ADDRESS')
        logger.debug('Setting REP_ADDRESS from Environment to: ' + state['REP_ADDRESS'])

    if 'REP_PUB_KEY' in os.environ:
        rep_pub_key = os.getenv('REP_PUB_KEY')
        logger.debug('Loading REP_PUB_KEY fron: ' + state['REP_PUB_KEY'])
        if os.path.exists(rep_pub_key):
            with open(rep_pub_key, 'r') as f:
                state['REP_PUB_KEY'] = f.read()
                logger.debug('Loaded REP_PUB_KEY from Environment')
    else:
        state['REP_PUB_KEY'] =load_public_key_text("../repository/credential_file")
    return state


def parse_args(state):
    parser = argparse.ArgumentParser()

    parser.add_argument("-k", '--key', nargs=1, help="Path to the key file")
    parser.add_argument("-r", '--repo', nargs=1, help="Address:Port of the repository")
    parser.add_argument("-v", '--verbose', help="Increase verbosity", action="store_true")
    parser.add_argument("-c", "--command", help="Command to execute")
    parser.add_argument("-s", "--username", help="Username")
    parser.add_argument("-d", "--date", help="Date")
    parser.add_argument('arg0', nargs='?', default=None)
    parser.add_argument('arg1', nargs='?', default=None)
    parser.add_argument('arg2', nargs='?', default=None)
    parser.add_argument('arg3', nargs='?', default=None)
    parser.add_argument('arg4', nargs='?', default=None)
    parser.add_argument('arg5', nargs='?', default=None)

    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.info('Setting log level to DEBUG')

    if args.key:
        if not os.path.exists(args.key[0]) or not os.path.isfile(args.key[0]):
            logger.error(f'Key file not found or invalid: {args.key[0]}')
            sys.exit(-1)

        with open(args.key[0], 'r') as f:
            state['REP_PUB_KEY'] = f.read()
            logger.info('Overriding REP_PUB_KEY from command line')

    if args.repo:
        state['REP_ADDRESS'] = args.repo[0]
        logger.info('Overriding REP_ADDRESS from command line')
    
    if args.command:
        logger.info("Command: " + args.command)
       
    return state, {'command': args.command, 'arg0': args.arg0, 'arg1': args.arg1, 'arg2': args.arg2, 'arg3': args.arg3, 'arg4': args.arg4, 'arg5': args.arg5}



def save(state):
    # Save state to file
    state_dir = os.path.join(os.path.expanduser('~'), '.sio')
    state_file = os.path.join(state_dir, 'state.json')

    if not os.path.exists(state_dir):
        logger.debug('Creating state folder')
        os.mkdir(state_dir)

    with open(state_file, 'w') as f:
        f.write(json.dumps(state, indent=4))
    logger.debug('State saved successfully')


def rep_subject_credentials(arg0,arg1):
    if arg1 is  None:
        print("arg0 is None")
        exit(1)
    password = arg0.encode()
    credentials_file = arg1

    key_gen(password,credentials_file)
    # logger.verbose("Credentials generated successfully")  # para debug
    
    print("Executing: rep_subject_credentials")

def encryptMessage(message):
    logger.debug(f"Encrypting message: {message}")
    state = load_state()
    message["created1"] = datetime.datetime.now().isoformat()
    server_public_key = serialization.load_pem_public_key(state["REP_PUB_KEY"].encode())
    client_private_key,client_public_key = key_gen_without_file()
    ciphertext, nonce, tag, salt = encrypt_data(json.dumps(message).encode(), client_private_key, server_public_key)
    signature, digest = sign_data(json.dumps(message).encode(), client_private_key)
    cipherMessage = {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "salt": salt.hex(),
        "signature": signature.hex(), 
        "digest": digest.hex(),
        "public_key":client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo).hex()
    }
    logger.debug(f"Message encrypted successfully: {cipherMessage}")
    return cipherMessage,client_private_key


def decryptData(data,client_private_key):
    logger.debug(f"Decrypting data: {data}")
    ciphertext = bytes.fromhex(data["ciphertext"])
    nonce = bytes.fromhex(data["nonce"])
    tag = bytes.fromhex(data["tag"])
    salt = bytes.fromhex(data["salt"])
    signature = bytes.fromhex(data["signature"])
    digest = bytes.fromhex(data["digest"])

    state = load_state()
    server_public_key = serialization.load_pem_public_key(state["REP_PUB_KEY"].encode())
    
    try:
        plaintext = decrypt_data(ciphertext, nonce, tag, salt, client_private_key, server_public_key)
        logger.debug("Data decrypted successfully")

        if verify_signature(signature, digest, server_public_key):
            decrypt = json.loads(plaintext.decode())
            logger.debug("Signature verification successful")
            return decrypt
        else:
            logger.error("Signature verification failed")
            return None
    except Exception as e:
        logger.error(f"Error decrypting data: {e}")
        return None


def encryptMessageWithSession(message, session):
    logger.debug(f"Encrypting message with session: {message}")
    state = load_state()
    session_id=session["session_id"]
    private_key = bytes.fromhex(session["private_key"])
    number=session["number"]
    message["number"] = number
    server_public_key = serialization.load_pem_public_key(state["REP_PUB_KEY"].encode())
    subject_private_key = load_private_key_from_bytes(private_key)
    ciphertext, nonce, tag, salt = encrypt_data(json.dumps(message).encode(), subject_private_key, server_public_key)
    signature, digest = sign_data(json.dumps(message).encode(), subject_private_key)
    cipherMessage = {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "salt": salt.hex(),
        "signature": signature.hex(), 
        "digest": digest.hex(),
        "session_id": session_id,
    }
    logger.debug(f"Message encrypted successfully: {cipherMessage}")
    return cipherMessage    
 

def decryptDataWithSession(data, session, session_file):
    logger.debug(f"Decrypting data with session: {data}")
    state = load_state()
    number=session["number"]
    private_key = bytes.fromhex(session["private_key"])
    ciphertext = bytes.fromhex(data["ciphertext"])
    nonce = bytes.fromhex(data["nonce"])
    tag = bytes.fromhex(data["tag"])
    salt = bytes.fromhex(data["salt"])
    signature = bytes.fromhex(data["signature"])
    digest = bytes.fromhex(data["digest"])

    state = load_state()    
    server_public_key = serialization.load_pem_public_key(state["REP_PUB_KEY"].encode())
    subject_private_key = load_private_key_from_bytes(private_key)
    
    plaintext = decrypt_data(ciphertext, nonce, tag, salt, subject_private_key, server_public_key)
    logger.debug("Data decrypted successfully")

    if verify_signature(signature, digest, server_public_key):
        decrypt = json.loads(plaintext.decode())
        session["number"] = number + 1
        with open(session_file, 'w') as file:
            file.write(json.dumps(session, indent=4))
        logger.debug("Signature verification successful")
        if number + 1 == decrypt["number"]:
            decrypt.pop("number")
        else:
            logger.error("Error: 5.")
            return None, 5
    return decrypt



def rep_create_org(organization, username, name, email, public_key_file):
    if public_key_file is None:
        logger.error("rep_create_org: Missing public key file argument.")
        return 1
    
    logger.debug("Loading public key from file")
    public_key = load_public_key_text(public_key_file)

    if public_key is None:
        logger.error("Public key could not be loaded")
        return 1

    message = {
        "organization": organization,
        "username": username,
        "name": name,
        "email": email,
        "public_key_file": public_key
    }
    logger.debug(f"Message: {message}")

    cipherMessage,private_key = encryptMessage(message)
    logger.debug("Message encrypted")

    try:
        state = load_state()
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        response = requests.post(f"http://{repo_address}/organization/create",json=cipherMessage)
        
        if response.status_code == 200:
            data = response.json()
            data = decryptData(data,private_key)
            logger.info("Organization created successfully")
            logger.debug(json.dumps(data, indent=4))
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to create organization",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2

def rep_create_session(organization_name, username, password, credentials_file, session_file):
    logger.debug("rep_create_session: Creating session")

    try:
        logger.debug(f"Loading private key from credentials file '{credentials_file}'.")
        client_private_key = load_private_key(password.encode(), credentials_file)
    except Exception as e:
        logger.error("Error loading private key: ", e)
        return 1
    
    if session_file is None:
        logger.error("Missing session file argument.")
        return 1

    session_id=secrets.token_hex(16)
    logger.debug(f"Session ID: {session_id}")

    message = {
        "organization": organization_name,
        "username": username,
        "encryption_key": load_public_key_text(credentials_file),
        "created_at" : datetime.datetime.now().isoformat(),
        "valid_until" : (datetime.datetime.now() + datetime.timedelta(minutes=60)).isoformat(),
        "session_id": session_id
    }

    logger.debug(f"Message: {message}")
    message,private_key = encryptMessage(message)

    try:
        state = load_state()
        logger.debug("Loaded state")
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        logger.debug("Sending session creation request to repository")
        response = requests.post(f"http://{repo_address}/session/create", json=message)
        
        if response.status_code == 200:
            logger.info("Session created successfully")
            data=response.json()
            data=decryptData(data,private_key)
            logger.debug(json.dumps(data, indent=4))

            logger.debug(f"Saving session ID to file '{session_file}'")
            
            session={"session_id":session_id,
                    "private_key":client_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()).hex(),
                    "number":0
                    }
            with open(session_file,"w") as file:
                file.write(json.dumps(session,indent=4))

            logger.debug("Session created successfully and saved to state file")
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to create session",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2

def rep_list_orgs():
    logger.debug("rep_list_orgs: Listing organizations")
    try:
        state = load_state()
        logger.debug("Loaded state")
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        logger.debug("Sending organization list request to repository")
        response = requests.get(f"http://{repo_address}/organization/list")
        
        if response.status_code == 200:
            organizations = response.json()
            logger.info(f"rep_list_orgs: Retrieved {len(organizations)} organizations successfully.")
            logger.info(json.dumps(response.json(), indent=4))
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to list organizations",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2


def rep_decrypt_file(encrypted_file, encryption_metadata=None):
    logger.debug("rep_decrypt_file: Decrypting file")

    state = load_state()
    try:
        logger.debug(f"Opening file '{encrypted_file}'")
        with open(encrypted_file, "r") as file:
            file_data = file.read()
    except FileNotFoundError:
        logger.error(f"File '{encrypted_file}' not found.")
        return 1
    
    if encryption_metadata is not None:
        logger.debug("Using encryption metadata from argument")
        metadata=json.loads(encryption_metadata)
    else:
        logger.debug("Using encryption metadata from state")
        metadata=state["metadataState"]

    try:
        algorithm = metadata["alg"]

        if algorithm != "AES-GCM":
            logger.error(f"Unsupported algorithm '{algorithm}'")
            return 1

        logger.debug("Decrypting file")
        file_data = bytes.fromhex(file_data)
        key = bytes.fromhex(metadata["key"])
        iv = bytes.fromhex(metadata["iv"])
        tag = bytes.fromhex(metadata["tag"])

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()

        original_file_data = decryptor.update(file_data) + decryptor.finalize()
        logger.debug("File decrypted successfully")
        print(original_file_data.decode())
        return 0

    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2

def rep_get_file(file_handle, fileName):
    logger.debug("rep_get_file: Getting file")
    message={"file_handle":file_handle}

    if file_handle is None:
        logger.error("rep_get_file: Missing file handle argument")
        return 1
    
    try:
        state = load_state()
        logger.debug("Loaded state")
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        logger.debug("Encrypting message")
        cipherMessage,private_key=encryptMessage(message)

        logger.debug("Sending get file request to repository")
        response = requests.get(f"http://{repo_address}/document/get_file", json=cipherMessage)
        
        if response.status_code == 200:
            logger.info("File retrieved successfully")
            data=response.json()
            data=decryptData(data,private_key)

            if fileName is not None:
                logger.debug(f"Saving file data to '{fileName}'")
                with open(fileName, "w") as file:
                    file.write((data)["file_data"])
            else:
                logger.debug("No file name provided, printing file data")
                print((data)["file_data"])

            logger.info("File saved successfully")
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to get File",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2

def rep_assume_role(args):
    # Second delivery
    print("Executing: rep_assume_role")

def rep_drop_role(args):
    # Second delivery
    print("Executing: rep_drop_role")

def rep_list_roles(args):
    # Second delivery
    print("Executing: rep_list_roles")

def rep_list_subjects(session_file, username):
    logger.debug("rep_list_subjects: Listing subjects")


    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1
    try:
        state = load_state()
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        request_data = {
            "session": session_id
        }

        if username:
            logger.debug(f"Adding username to request data: {username}")
            request_data["username"] = username

        request_data=encryptMessageWithSession(request_data, session)
        logger.debug("Sending list subjects request to repository")
        response = requests.get(f"http://{repo_address}/subject/list", json=request_data)

        if response.status_code == 200:
            logger.info("Subjects listed successfully")
            data=response.json()
            data=decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to list subjects",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2

def rep_list_role_subjects(args):
    # Second delivery
    print("Executing: rep_list_role_subjects")

def rep_list_subject_roles(args):
    # Second delivery
    print("Executing: rep_list_subject_roles")

def rep_list_role_permissions(args):
    # Second delivery
    print("Executing: rep_list_role_permissions")

def rep_list_permission_roles(args):
    # Second delivery
    print("Executing: rep_list_permission_roles")

def rep_list_docs(session_file, username, d):
    logger.debug("rep_list_docs: Listing documents")
    state = load_state()

    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1
    
    condition = None
    date = None
    try:
        if d is None:
            condition = None
            date_str = None
        else:
            condition = d[0]
            date_str = d[1]
            if date_str:
                try:
                    date = datetime.datetime.strptime(date_str, "%d-%m-%Y").strftime("%d-%m-%Y")
                except ValueError:
                    logger.error("Invalid date format, expected DD-MM-YYYY")
                    return 1
            else:
                date = None
    except Exception as e:
        logger.error(f"Error date arg: {str(e)}")
        return 1
    logger.debug("Condition: %s, Date: %s, Data: %s", condition, date, d)

    try:
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        message = {
        "session": session_id,
        "username": username,
        "condition": condition,
        "date": date,
        }

        logger.debug("Message: ", message)
        logger.debug("Encrypting message")

        message = encryptMessageWithSession(message, session)
        logger.debug("Sending list documents request to repository")
        response = requests.get(f"http://{repo_address}/document/list", json=message)
        
        if response.status_code == 200:
            logger.info("Documents listed successfully")
            data = response.json()
            data = decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to list documents",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2

def rep_add_subject(session_file, username, name, email, public_key_file):
    logger.debug("rep_add_subject: Adding subject")
    state = load_state()

    try:
        public_key = load_public_key_text(public_key_file)
        logger.debug("Public key loaded successfully")
        if public_key is None:
            logger.error(f"Error reading public key file: {e}")
            return 1          
    except Exception as e:
        logger.error(f"Error reading public key file: {e}")
        return 1

    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1

    message = {
        "session": session_id,
        "username": username,
        "name": name,
        "email": email,
        "public_key": public_key,
    }


    try:
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        logger.debug("Encrypting message")
        message=encryptMessageWithSession(message, session)
        logger.debug("Sending add subject request to repository")
        response = requests.post(f"http://{repo_address}/subject/add", json=message)
        
        if response.status_code == 200:
            logger.info("Subject added successfully")
            data=response.json()
            data=decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to add subject",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2


def rep_suspend_subject(session_file, username):
    logger.debug("rep_suspend_subject: Suspending subject")
    state = load_state()

    
    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1

    message = {
        "session": session_id,
        "username": username,
    }

    try:
        state = load_state()
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        message=encryptMessageWithSession(message, session)
        logger.debug("Encrypted message: ", message)
        logger.debug("Sending suspend subject request to repository")
        response = requests.post(f"http://{repo_address}/subject/suspend", json=message)

        if response.status_code == 200:
            logger.info("Subject suspended successfully")
            data = response.json()
            data = decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to suspend subject",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2


def rep_activate_subject(session_file, username):
    logger.debug("rep_activate_subject: Activating subject")
    state = load_state()


    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1
    
    message = {
        "session": session_id,
        "username": username,
    }

    try:
        state = load_state()
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        message=encryptMessageWithSession(message, session) 
        logger.debug("Sending activate subject request to repository")
        response = requests.post(f"http://{repo_address}/subject/activate", json=message)

        if response.status_code == 200:
            logger.info("Subject activated successfully")
            data = response.json()
            data = decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to acitvate subject",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2


def rep_add_role(args):

    # Second delivery
    
    print("Executing: rep_add_role")


def rep_suspend_role(args):
    
    # Second delivery
    
    print("Executing: rep_suspend_role")


def rep_reactivate_role(args):
    
    # Second delivery
    
    print("Executing: rep_reactivate_role")


def rep_add_permission(args):
    
    # Second delivery
    
    print("Executing: rep_add_permission")


def rep_remove_permission(args):
    
    # Second delivery
    
    print("Executing: rep_remove_permission")


def rep_add_permission(args):
    
    # Second delivery
    
    print("Executing: rep_add_permission")


def rep_remove_permission(args):
    
    # Second delivery
    
    print("Executing: rep_remove_permission")


def rep_add_doc(session_file, doc_name, file_name):
    logger.debug("rep_add_doc: Adding document")
    state = load_state()

    
    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1

    try:
        logger.debug(f"Reading file '{file_name}'")
        with open(file_name, 'rb') as f:
            file_data = f.read()
    except FileNotFoundError:
        logger.error("File not Found")
        return 1
    try:
        
        message = {
            "session":session_id,
            "doc_name": doc_name,
            "file_data": file_data.decode(),
        }

        message = encryptMessageWithSession(message, session) 
        logger.debug("Message: ", message)

        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug("Repository address: {repo_address}")

        logger.debug("Sending add doc request to repository")
        response = requests.post(f"http://{repo_address}/document/add", json=message)

        if response.status_code == 200:
            logger.info("Document added and metadata saved to state file")
            data = response.json()
            data = decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))   
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to add doc",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2
            

def rep_get_doc_metadata(session_file, doc_name):
    logger.debug("rep_get_doc_metadata: Getting document metadata")
    
    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1

    message = {
        "session": session_id,
        "doc_name": doc_name,
    }

    try:
        state = load_state()
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        message = encryptMessageWithSession(message, session) 
        logger.debug("Sending get doc metadata request to repository")
        response = requests.get(f"http://{repo_address}/document/get_metadata",json=message)
        
        if response.status_code == 200: 
            logger.info("Metadata retrieved successfully")
            data = response.json()
            data = decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))           
            metadata = data["metadata"]
            metadataState={"key": metadata["key"] ,
                           "alg": metadata["alg"],
                            "iv": metadata["iv"] ,
                            "tag": metadata["tag"] 
                            }
            state = load_state()
            state["metadataState"] = metadataState
            save(state)
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to get metadata",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2


def rep_get_doc_file(session_file, doc_name, file_name=None):
    logger.debug("rep_get_doc_file: Getting document file")

    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1


    message = {
        "session": session_id,
        "doc_name": doc_name,
    }

    file_handle=None
    metadataState=None
    try:
        state = load_state()
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        message=encryptMessageWithSession(message, session) 
        logger.debug("Sending get doc metadata request to repository")
        response = requests.get(f"http://{repo_address}/document/get_metadata",json=message)
        
        if response.status_code == 200: 
            logger.info("Metadata retrieved successfully")
            data = response.json()
            data = decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))  
            state = load_state()         
            metadata = data["metadata"]
            if metadata["deleter"] is not None:
                print("Error: file_handle has delete")
                return 1
            file_handle=metadata["file_handle"]
            metadataState={"key": metadata["key"] ,
                           "alg": metadata["alg"],
                            "iv": metadata["iv"] ,
                            "tag": metadata["tag"] 
                            }
            state["metadataState"] = metadataState
            save(state)

        else:
            logger.error(json.dumps({
                "error": "Failed to get metadata",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2

    message={"file_handle":file_handle}

    if file_handle is None:
        logger.error("No file handle")
        return 1
    
    try:
        state = load_state()
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        cipherMessage,private_key=encryptMessage(message)
        logger.debug("Sending get file request to repository")
        response = requests.get(f"http://{repo_address}/document/get_file", json=cipherMessage)
        
        if response.status_code == 200:
            logger.info("File retrieved successfully")
            data=response.json()
            data=decryptData(data,private_key)
            logger.info(json.dumps(data, indent=4))

        else:
            logger.error(json.dumps({
                "error": "Failed to get File",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2
    
    file_data=data["file_data"]
    metadata=metadataState
    try:
        algorithm = metadata["alg"]

        if algorithm != "AES-GCM":
            logger.error(f"Unsupported algorithm '{algorithm}'")
            return 1

        file_data = bytes.fromhex(file_data)
        key = bytes.fromhex(metadata["key"])
        iv = bytes.fromhex(metadata["iv"])
        tag = bytes.fromhex(metadata["tag"])

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()
        original_file_data = decryptor.update(file_data) + decryptor.finalize()
        logger.debug("File decrypted successfully")

        original_file_data=original_file_data.decode()
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": "Decryption error."
        }, indent=4))
        return 2

    if file_name is not None:
        logger.debug(f"Writing file '{file_name}'")
        with open(file_name, "w") as file:
            file.write(original_file_data)
    else:
        logger.info(original_file_data)
    return 0


def rep_delete_doc(session_file,doc_name):
    logger.debug("rep_delete_doc: Deleting document")
    state = load_state()

    
    try:
        logger.debug(f"Opening session file '{session_file}'")
        with open(session_file, "r") as file:
            session = json.loads(file.read())
            session_id=session["session_id"]
    except Exception as e:
        logger.error(f"Error while opening the file {session_file}: {str(e)}")
        return 1

    message = {
        "session": session_id,
        "doc_name": doc_name,
    }

    try:
        state = load_state()
        repo_address = state.get("REP_ADDRESS", "localhost:5000")
        logger.debug(f"Repository address: {repo_address}")

        message=encryptMessageWithSession(message, session)
        logger.debug("Sending delete doc request to repository")
        response = requests.delete(f"http://{repo_address}/document/remove", json=message)
        
        if response.status_code == 200:
            logger.info("Document deleted successfully")
            data = response.json()
            data = decryptDataWithSession(data, session,session_file)
            logger.info(json.dumps(data, indent=4))
            return 0
        else:
            logger.error(json.dumps({
                "error": "Failed to list documents",
                "status_code": response.status_code,
                "details": response.text
            }, indent=4))
            return -1
    except Exception as e:
        logger.error(json.dumps({
            "error": "An exception occurred",
            "details": str(e)
        }, indent=4))
        return 2


def rep_acl_doc(args):
    # Second delivery
    print("Executing: rep_acl_doc")

def main():
    state = load_state()
    print(state)
    state = parse_env(state)
    save(state)
    state, args = parse_args(state)
    logger.debug("Arguments: " + str(args))

    # Chama a função apropriada com os argumentos
    match args["command"]:
        case "rep_subject_credentials":
            exitCode = rep_subject_credentials(args["arg0"], args["arg1"])
        case "rep_create_org":
            exitCode = rep_create_org(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
        case "rep_list_orgs":
            exitCode = rep_list_orgs()
        case "rep_add_doc":
            exitCode = rep_add_doc(args["arg0"], args["arg1"], args["arg2"])
        case "rep_get_file":
            exitCode = rep_get_file(args["arg0"], args["arg1"])
        case "rep_create_session":
            exitCode = rep_create_session(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
        case "rep_list_docs":
            exitCode = rep_list_docs(args["arg0"],args.get("username",None),args.get("date",None))
        case "rep_get_doc_metadata":
            exitCode = rep_get_doc_metadata(args["arg0"],args["arg1"])
        case "rep_delete_doc":
            exitCode = rep_delete_doc(args["arg0"],args["arg1"])
        case "rep_add_subject":
            exitCode = rep_add_subject(args["arg0"], args["arg1"], args["arg2"], args["arg3"], args["arg4"])
        case "rep_suspend_subject":
            exitCode = rep_suspend_subject(args["arg0"], args["arg1"])
        case "rep_activate_subject":
            exitCode = rep_activate_subject(args["arg0"], args["arg1"])
        case "rep_list_subjects":
            exitCode = rep_list_subjects(args["arg0"], args["arg1"])
        case "rep_get_doc_file":
            if args["arg2"]:
                exitCode = rep_get_doc_file(args["arg0"], args["arg1"], args["arg2"])
            else:
                exitCode = rep_get_doc_file(args["arg0"], args["arg1"])
        case "rep_decrypt_file":
            exitCode = rep_decrypt_file(args["arg0"], args["arg1"])

        case _:
            print(f"Unknown command: {args['command']}")
            # parser.print_help()
            sys.exit(1)
    return exitCode


if __name__ == "__main__":
    sys.exit(main())
