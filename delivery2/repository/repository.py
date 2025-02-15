from bson import ObjectId
from flask import Flask, request
import json
import uuid
from pymongo import MongoClient
import datetime
from hashlib import sha256
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from KeysGenerator import *

REP_PUB_KEY = os.getenv("REP_PUB_KEY",default="credential_file")
REP_ADDRESS = os.getenv("REP_ADDRESS",default="0.0.0.0:5000")

(host, port) = REP_ADDRESS.split(":")

DOC_ACL = "DOC_ACL"
DOC_READ = "DOC_READ"
DOC_NEW = "DOC_NEW"
DOC_DELETE = "DOC_DELETE"
ROLE_ACL = "ROLE_ACL"
SUBJECT_NEW = "SUBJECT_NEW"
SUBJECT_DOWN = "SUBJECT_DOWN"
SUBJECT_UP = "SUBJECT_UP"
ROLE_NEW = "ROLE_NEW"
ROLE_DOWN = "ROLE_DOWN"
ROLE_UP = "ROLE_UP"
ROLE_MOD = "ROLE_MOD"

MANAGER="Manager"
permissionList=[ROLE_ACL, SUBJECT_NEW, SUBJECT_DOWN, SUBJECT_UP, DOC_NEW, ROLE_NEW, ROLE_DOWN, ROLE_UP, ROLE_MOD]
permissionListDOC=[DOC_ACL, DOC_READ, DOC_DELETE]
app = Flask(__name__)

# Our Database
# client = MongoClient("mongodb://localhost:27017/") # For local testing
client = MongoClient("mongodb://mongodb:27017/")
db = client['repository']

# Clear
# for collection_name in db.list_collection_names():
#     collection = db[collection_name]
#     collection.delete_many({}) 

organizations_collection = db['organizations']
sessions_collection = db['sessions']
documents_collection = db['documents']  # public part of the documents
documents_private_collection = db['documents_private']  # private part of the documents
subjects_collection = db['subjects']
localPass = "sercurity pass2"
global_public_key = None
key_gen(b"localPass", REP_PUB_KEY)
repository_private_key, repository_public_key = key_load(b"localPass", REP_PUB_KEY)
listMessages_collection = db['listMessages_collection']


@app.route("/organization/list", methods=["GET"])
def org_list():
    try:
        organizations = list(
            organizations_collection.find( {}, { "_id": 0, "name": 1 }, ))

        return json.dumps(organizations), 200
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


def decryptDataToData(data):
    ciphertext = bytes.fromhex(data["ciphertext"])
    nonce = bytes.fromhex(data["nonce"])
    tag = bytes.fromhex(data["tag"])
    salt = bytes.fromhex(data["salt"])
    signature = bytes.fromhex(data["signature"])
    digest = bytes.fromhex(data["digest"])
    public_key = bytes.fromhex(data["public_key"])
    client_public_key=serialization.load_pem_public_key(public_key)
    try:
        plaintext = decrypt_data(ciphertext, nonce, tag, salt, repository_private_key, client_public_key)
        if verify_signature(signature, digest, client_public_key):
            data = json.loads(plaintext.decode())
    except InvalidSignature:
        return None, 1
    except Exception as e:
        return None, 2
    created1 = datetime.datetime.fromisoformat(data["created1"])
    if created1 + datetime.timedelta(minutes=1) > datetime.datetime.now():
        data.pop("created1")
    else:
        return None, 5
    return data, client_public_key

def encryptMessage(message, client_public_key):
    ciphertext, nonce, tag, salt = encrypt_data(json.dumps(message).encode(), repository_private_key, client_public_key)
    signature, digest = sign_data(json.dumps(message).encode(), repository_private_key)
    cipherMessage = {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "salt": salt.hex(),
        "signature": signature.hex(), 
        "digest": digest.hex()
    }
    return cipherMessage    


def decryptDataToDataWithSession(data):
    ciphertext = bytes.fromhex(data["ciphertext"])
    nonce = bytes.fromhex(data["nonce"])
    tag = bytes.fromhex(data["tag"])
    salt = bytes.fromhex(data["salt"])
    signature = bytes.fromhex(data["signature"])
    digest = bytes.fromhex(data["digest"])
    session_id = data.get("session_id")
    session = sessions_collection.find_one({"_id": session_id})
    subject_public_key=serialization.load_pem_public_key(session["public_key"].encode())

    try:
        plaintext = decrypt_data(ciphertext, nonce, tag, salt, repository_private_key, subject_public_key)
        if verify_signature(signature, digest, subject_public_key):
            data = json.loads(plaintext.decode())
    except InvalidSignature:
        return None, 1
    except Exception as e:
        return None, 2
    if session["number"] == data["number"]:
        data.pop("number")
    else:
        return None, 5
    return data, subject_public_key

def encryptMessageWithSession(message, subject_public_key, session_id):
    session = sessions_collection.find_one({"session_id": session_id})
    number = session["number"]
    message["number"] = number + 1
    ciphertext, nonce, tag, salt = encrypt_data(json.dumps(message).encode(), repository_private_key, subject_public_key)
    signature, digest = sign_data(json.dumps(message).encode(), repository_private_key)
    cipherMessage = {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex(),
        "tag": tag.hex(),
        "salt": salt.hex(),
        "signature": signature.hex(), 
        "digest": digest.hex()
    }
    sessions_collection.update_one(
        {"session_id": session_id},
        {"$inc": {"number": 1}}
    )
    return cipherMessage    


@app.route("/organization/create", methods=["POST"])
def org_create():
    try:
        data = request.get_json() 
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        data, public_key = decryptDataToData(data)
        if data is None:
            if public_key == 3:
                return json.dumps({"error": "State id_client error"}), 402

        organizationName = data.get("organization")
        username = data.get("username")
        name = data.get("name")
        email = data.get("email")
        public_key_file = data.get("public_key_file")
        
        if organizations_collection.find_one({"name": organizationName}):
            return json.dumps({"error": "An exception occurred", "details": f"Organization with name '{organizationName}' already exists."}), 400

        subjects_collection.insert_one({"username": username, "name": name, "email": email, "public_key": public_key_file})

        organization_data = {
            "name": organizationName,
            "creator": username,
            "subjects": {username: {"status": "up", "public_key": public_key_file, "roles": [MANAGER]}},
            "documents": [],
            "roles": {MANAGER: "up"},
            "acl": { ROLE_ACL: [MANAGER], SUBJECT_NEW: [MANAGER], SUBJECT_DOWN: [MANAGER], SUBJECT_UP: [MANAGER],   DOC_NEW: [MANAGER], ROLE_NEW: [MANAGER], ROLE_DOWN: [MANAGER], ROLE_UP: [MANAGER], ROLE_MOD: [MANAGER]},
            "public_key_file" : public_key_file
        }
        organizations_collection.insert_one(organization_data)

        message={"message": "Organization created successfully"}
        cipherMessage=encryptMessage(message, public_key)
        return json.dumps(cipherMessage), 200
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/session/create", methods=["POST"])
def session_create():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, public_key = decryptDataToData(data)
        if data is None:
            if public_key == 3:
                return json.dumps({"error": "State id_client error"}), 402

        organization = data.get("organization")
        username = data.get("username")
        session_id = data.get("session_id")
        encryption_key = data.get("encryption_key")
        created_at = data.get("created_at")
        valid_until = data.get("valid_until")

        if  organizations_collection.find_one({"name": organization}) is None:
            return json.dumps({"error": "An exception occurred", "details": f"Organization with name '{organization}' no exists."}), 400
        
        organizationSession = organizations_collection.find_one({"name": organization})

        subject = subjects_collection.find_one({"username": username})
        if not subject or  username not in  organizationSession["subjects"].keys():
            return json.dumps({"error": "User not found"}), 400
        
        # if suspended
        if organizationSession["subjects"][username]["status"] == "down":
            return json.dumps({"error": "Subject is suspended"}), 400

        if not(sha256(organizationSession["subjects"][username]["public_key"].encode()).hexdigest() == sha256(encryption_key.encode()).hexdigest()):
            return json.dumps({"error": "Public key was diferent to in organization with this subject"}), 400
        
        session_data = {
            "_id": session_id,
            "session_id": session_id,
            "organization": organization,
            "username":username,
            "created_at":created_at,
            "valid_until":valid_until,
            "public_key":encryption_key,
            "number":0,
            "roles":[],
        }
        created_at = datetime.datetime.fromisoformat(session_data["created_at"])
        if created_at + datetime.timedelta(minutes=5) < datetime.datetime.now():
            return json.dumps({"error": ""}), 400
        session = sessions_collection.find_one({"_id": session_data["_id"]})
        if session:
            valid_until = datetime.datetime.fromisoformat(session["valid_until"])
            if valid_until < datetime.datetime.now():
                sessions_collection.delete_one({"_id": session["_id"]})
            else:
                return json.dumps({"error": "Session exist found"}), 400
        
        sessions_collection.insert_one(session_data)
        
        message = {"message": "Session created successfully", "session_id": session_data["_id"]}
        cipherMessage=encryptMessage(message, public_key)
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


def getSession(session_id):
    session_data = sessions_collection.find_one({"_id": session_id})
    if session_data:
        valid_until = datetime.datetime.fromisoformat(session_data["valid_until"])
        organization = organizations_collection.find_one({"name": session_data["organization"]})
        if valid_until < datetime.datetime.now():
            sessions_collection.delete_one({"_id": session_id})
            return None  
        if organization['subjects'][session_data["username"]]["status"] == "down":
            return None
        return session_data
    else:
        return None
    

@app.route("/document/decrypt_file", methods=["POST"])
def decrypt_file():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        encrypted_file_handle = data.get("encrypted_file_handle")
        key = bytes.fromhex(data.get("key"))
        iv = bytes.fromhex(data.get("iv"))
        tag = bytes.fromhex(data.get("tag"))
        algorithm = data.get("algorithm", "AES-GCM")

        if algorithm != "AES-GCM":
            return json.dumps({"error": f"Unsupported algorithm '{algorithm}'"}), 400

        file_path = f"files/{encrypted_file_handle}"
        try:
            with open(file_path, "rb") as file:
                encrypted_file_data = file.read()
        except FileNotFoundError:
            return json.dumps({"error": "Encrypted file not found"}), 404

        try:
            decryptor = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag)
            ).decryptor()
            decrypted_content = decryptor.update(encrypted_file_data) + decryptor.finalize()
        except Exception as e:
            return json.dumps({"error": "Decryption failed", "details": str(e)}), 400
        return decrypted_content, 200, {'Content-Type': 'application/octet-stream'}

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/document/get_file", methods=["GET"])
def get_file():
    try:
        data = request.get_json()
        data, public_key = decryptDataToData(data)
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        file_handle = data.get("file_handle")
        if not file_handle:
            return json.dumps({"error": "Missing required fields"}), 400
                
        directory = os.path.abspath("files")
        file_path = os.path.abspath(os.path.join(directory, file_handle))
        if not file_path.startswith(directory):
            return json.dumps({"error": "File not found"}), 404
        try:
            with open(file_path, "rb") as file:
                file_data = file.read()
        except FileNotFoundError:
            return json.dumps({"error": "File not found"}), 404
        message={"file_data": file_data.hex()}
        cipherMessage=encryptMessage(message, public_key)
        return json.dumps(cipherMessage), 200
    
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/subject/list", methods=["GET"])
def list_subjects():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error":"session not stored"}), 400
        
        username = data.get("username")

        organization_name = session.get("organization")
        if not organization_name:
            return json.dumps({"error": "Invalid session data"}), 400

        organization = organizations_collection.find_one({"name": organization_name})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        subjects_status = organization.get("subjects")

        if username:
            if username in subjects_status:
                subject = subjects_collection.find_one({"username": username}, {"_id": 0})
                subject_status = subjects_status.get(username)
                subject["status"] = {k: v for k, v in subject_status.items() if k != "roles" and k != "public_key"}
                subject.pop("public_key", None)
                subjects = [subject]
        else:
            subjects = []
            for username, status in subjects_status.items():
                subject = subjects_collection.find_one({"username": username}, {"_id": 0, "public_key": 0})
                if subject:
                    subject["status"] = {k: v for k, v in status.items() if k != "roles" and k != "public_key"}
                    subjects.append(subject)

        cipherMessage = encryptMessageWithSession({"subjects": subjects}, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/role/assume", methods=["POST"])
def rep_assume_role():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400

        username = session.get("username")
        role = data.get("role")
        
        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        if role not in organization['subjects'][username]['roles']:
            return json.dumps({"error": f"Role {role} not found in subject"}), 400
        
        if organization['roles'][role] == "down":
            return json.dumps({"error": f"Role {role} is suspended and cannot be assumed"}), 400

        if role in session["roles"]:
            return json.dumps({"error": f"Role {role} already assigned to the session"}), 400

        sessions_collection.update_one(
            {"session_id": data["session"]},
            {"$push": {"roles": role}}
        )

        message = {"message": f"Role {role} assumed successfully"} 
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/role/drop", methods=["POST"])
def rep_drop_role():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400

        username = session.get("username")
        role = data.get("role")

        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})

        subject = subjects_collection.find_one({"username": username})
        if not subject or not username in organization['subjects']:
            return json.dumps({"error": "Subject not found"}), 400

        if role not in session["roles"]:
            return json.dumps({"error": f"Role {role} not associated with the session"}), 400
        
        sessions_collection.update_one(
            {"session_id": data["session"]},
            {"$pull": {"roles": role}} 
        )

        message = {"message": f"Role {role} dropped successfully"}
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/role/list", methods=["GET"])
def list_roles():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400
        
        cipherMessage = encryptMessageWithSession({"roles":session["roles"]}, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/role/list_subjects", methods=["GET"])
def rep_list_role_subjects():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400

        role = data.get("role")
        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        subjectsInOrg = organization["subjects"]
        
        subjects_list = []
        for username,subject in subjectsInOrg.items():
            if role in subject["roles"]:
                status = subject["status"]
                subjects_list.append((username, status))
        if not subjects_list:
            return json.dumps({"error": f"No subjects found with role {role}"}), 404

        cipherMessage = encryptMessageWithSession({"subjects_list":subjects_list}, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/subject/list_roles", methods=["GET"])
def rep_list_subject_roles():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400

        username = data.get("username")

        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})

        subject = subjects_collection.find_one({"username": username})
        if not subject or not username in organization['subjects']:
            return json.dumps({"error": "Subject not found"}), 4000

        roles = organization["subjects"][username]["roles"]

        cipherMessage = encryptMessageWithSession({"roles":roles}, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/role/list_permissions", methods=["GET"])
def list_role_permissions():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400

        role = data.get("role")

        organization_name = session["organization"]

        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        aclInOrg=organization["acl"]

        permissions_list = []
        for acl, listRoles in aclInOrg.items():
            if role in listRoles:
                permissions_list.append(acl)

        document_acls = {}
        for doc in organization["documents"]:
            acl = documents_collection.find_one({"name": doc})["acl"]
            for permission, roles in acl.items():
                if permission not in document_acls:
                    document_acls[permission] = []
                if role in roles:
                    document_acls[permission].append(doc)

        cipherMessage = encryptMessageWithSession({"permissions_list": permissions_list, "document_acls": document_acls}, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/permission/list_roles", methods=["GET"])
def list_permission_roles():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400

        permission = data.get("permission")
        if not permission:
            return json.dumps({"error": "Missing 'permission' field in request"}), 400
        
        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        aclInOrg=organization["acl"]
        if permission not in aclInOrg:
            return json.dumps({"error": f"Permission '{permission}' not found in ACL"}), 400
        
        roles_list = aclInOrg[permission]

        cipherMessage = encryptMessageWithSession({"roles_list":roles_list}, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/document/list", methods=["GET"])
def list_docs():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return {"error":"session not stored"}, 400

        organization_name = session["organization"]
        username = data.get("username")
        condition = data.get("condition")
        date_str = data.get("date")
        
        date = None
        if date_str:
            try:
                date = datetime.datetime.strptime(date_str, "%d-%m-%Y")
            except ValueError:
                return json.dumps({"error": "Invalid date format. Use 'dd-mm-yyyy'"}), 400
        organization = organizations_collection.find_one({"name":organization_name})
        listDocs = []
        #nt/ot/et
        for docName in organization["documents"]:
            document = documents_collection.find_one({"name":docName},{"_id":0})
            if username is not None: 
                if document["creator"] != username:
                    continue
            if condition is not None:
                match condition:
                    case "nt":  # Newer than
                        if document["create_date"].date() <= date.date():
                            continue
                    case "ot":  # Older than
                        if document["create_date"].date() >= date.date():
                            continue
                    case "et":  # Equal to
                        if document["create_date"].date() != date.date():
                            continue
            document["create_date"] = document["create_date"].isoformat()
            listDocs.append(document) 
            
        message={"message": "List documents successfully", "list": listDocs}
        cipherMessage = encryptMessageWithSession(message,subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/subject/add", methods=["POST"])
def add_subject():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session=getSession(data.get("session"))
        if session is None:
            return {"error":"session not stored"}, 400
        
        username = data.get("username")
        name = data.get("name")
        email = data.get("email")
        public_key = data.get("public_key")

        if not session or not conferSession(session, SUBJECT_NEW):
            return json.dumps({"error": "Session don't have the permission."}), 500
        
        if not all([username, name, email, public_key]):
            return json.dumps({"error": "Missing required fields"}), 400
        
        organization = organizations_collection.find_one({"name": session["organization"]})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        if subjects_collection.find_one({"username": username}):
            return json.dumps({"error": "An exception occurred", "details": f"Subject with username '{username}' already exists."}), 500
        
        result = subjects_collection.insert_one({
            "username": username,
            "name": name,
            "email": email,
            "public_key": public_key
        })

        organizations_collection.update_one(
            {"name": session["organization"]},
            {"$set": {f"subjects.{username}": {"status": "up", "public_key": public_key,"roles":[]}}}
        )
        
        message = {"message": "Subject added successfully"}
        cipherMessage = encryptMessageWithSession(message,subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200
    
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/subject/suspend", methods=["POST"])
def suspend_subject():
    try:
        data = request.get_json()
        if not data:    
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data) 
        session = getSession(data.get("session"))
        if session is None:
            return {"error":"session not stored"}, 400
        username = data.get("username")

        if not session or not conferSession(session, SUBJECT_DOWN):
            return json.dumps({"error": "Session doesn't have the permission."}), 500
        
        if not username:
            return json.dumps({"error": "Missing required fields"}), 400
        
        organization = organizations_collection.find_one({"name": session["organization"]})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        subject = organization.get("subjects").get(username)
        if not subject:
            return json.dumps({"error": "Subject not found"}), 400

        subject_status = subject.get("status")
        if subject_status == "down":
            return json.dumps({"error": "Subject already suspended."}), 400
        if MANAGER in subject["roles"]:
            counterManagers = 0
            subjects=organization["subjects"]
            for usernameSub,valueSub in subjects.items():
                if MANAGER in valueSub["roles"] and valueSub["status"]=="up":
                    counterManagers += 1

            if counterManagers == 1:
                return json.dumps({"error": "The last subject which role Manager cannot be suspend."}), 400  

        organizations_collection.update_one(
            {"name": session["organization"]},
            {"$set": {f"subjects.{username}.status": "down"}}
        )

        message={"message": "Subject suspended successfully"}
        cipherMessage=encryptMessageWithSession(message, subject_public_key,session["session_id"]) 
        return json.dumps(cipherMessage), 200
    
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500
    

@app.route("/subject/activate", methods=["POST"])
def activate_subject():
    try:
        data = request.get_json()
        if not data:    
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session=getSession(data.get("session"))
        if session is None:
            return {"error":"session not stored"}, 400
        username = data.get("username")

        if not session or not conferSession(session, SUBJECT_UP):
            return json.dumps({"error": "Session doesn't have the permission."}), 500
        
        if not username:
            return json.dumps({"error": "Missing required fields"}), 400
        
        organization = organizations_collection.find_one({"name": session["organization"]})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        subject_status = organization.get("subjects").get(username).get("status")
        if not subject_status:
            return json.dumps({"error": "Subject not found"}), 400
        
        if subject_status == "up":
            return json.dumps({"error": "An exception occurred", "details": "Subject already active."}), 500
        
        organizations_collection.update_one(
            {"name": session["organization"]},
            {"$set": {f"subjects.{username}.status": "up"}}
        )

        message = {"message": "Subject activated successfully"}
        cipherMessage = encryptMessageWithSession(message,subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/role/add", methods=["POST"])
def add_role():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400

        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400

        if not conferSession(session, ROLE_NEW):
            return json.dumps({"error": "Session doesn't have the permission."}), 500

        role = data.get("role")
        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        if role in organization['roles']:
            return json.dumps({"error": f"Role {role} already exists in to the organization"}), 400

        organizations_collection.update_one(
            {"name": organization_name},
            {"$set": {"roles." + role: "up"}}
        )

        message = {"message": f"Role {role} add successfully"} 
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/role/suspend", methods=["POST"])
def suspend_role():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400
        
        if not session or not conferSession(session, ROLE_DOWN):
            return json.dumps({"error": "Session doesn't have the permission."}), 500
        
        role = data.get("role")
        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        if role not in organization['roles']:
            return json.dumps({"error": "Role not found in organization"}), 400        
        if role == MANAGER:
            return json.dumps({"error": "Role Manager cannot be suspended."}), 400

        if organization['roles'][role] == "down":
            return json.dumps({"error": "Role already suspended."}), 500
        
        organizations_collection.update_one(
            {"name": organization_name},
            {"$set": {f"roles.{role}": "down"}}
        )
        
        message = {"message": f"Role {role} suspended successfully"}
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/role/reactivate", methods=["POST"])
def reactivate_role():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400
        
        if not session or not conferSession(session, ROLE_UP):
            return json.dumps({"error": "Session doesn't have the permission."}), 500
        
        role = data.get("role")
        if not role:
            return json.dumps({"error": "Missing required fields"}), 400
        
        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        if role not in organization['roles']:
            return json.dumps({"error": "Role not found in organization"}), 400
        if organization['roles'][role] == "up":
            return json.dumps({"error": "Role already active."}), 500
        
        organizations_collection.update_one(
            {"name": organization_name},
            {"$set": {f"roles.{role}": "up"}}
        )
        
        message = {"message": f"Role {role} reactivated successfully"}
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/permission/add", methods=["POST"])
def add_permission():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400
        
        if not session or not conferSession(session, ROLE_MOD):
            return json.dumps({"error": "Session doesn't have the permission."}), 500
        
        role = data.get("role")
        permission = None
        username = None
        arg03 = data.get("arg03")
        if arg03 in permissionList:
            permission = arg03
        else:
            username = arg03

        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        if role not in organization['roles']:
            return json.dumps({"error": "Role not found in organization"}), 400        

        if permission is not None:
            if not session or not conferSession(session, ROLE_ACL):
                return json.dumps({"error": "Session doesn't have the permission ROLE_ACL to Modify the ACL."}), 500
            
            if organization['roles'][role] == "down":
                return json.dumps({"error": "Role is suspended"}), 400

            permissionRoles = organization["acl"][permission]
            if role in permissionRoles:
                return json.dumps({"error": "Role have the permission"}), 400  

            organizations_collection.update_one(
                {"name": session["organization"]},
                {"$push": {f"acl.{permission}": role}}
            )
            message = {"message": f"Role {role} add permission {permission} successfully"}

        if username is not None:
            if username not in organization["subjects"]: 
                return json.dumps({"error": "Username not found in organization"}), 400  
            roles = organization["subjects"][username]["roles"]

            if organization['roles'][role] == "down":
                return json.dumps({"error": "Role is suspended"}), 400

            if role in roles:
                return json.dumps({"error": f"Role {role} was found in subject"}), 400
            organizations_collection.update_one(
                {"name": session["organization"]},
                {"$push": {f"subjects.{username}.roles": role}}
            )
            message = {"message": f"Role {role} was add in {username} successfully"}
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/permission/remove", methods=["POST"])
def remove_permission():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400
        
        if not session or not conferSession(session, ROLE_MOD):
            return json.dumps({"error": "Session doesn't have the permission."}), 500
        
        role = data.get("role")
        permission = None
        username = None
        arg03 = data.get("arg03")
        if arg03 in permissionList:
            permission = arg03
            if role == MANAGER:
                return json.dumps({"error": "Permission removal not allowed for role MANAGER"}), 400
        else:
            username = arg03

        organization_name = session.get("organization")
        organization = organizations_collection.find_one({"name": organization_name})
        if not organization:
            return json.dumps({"error": "Organization not found"}), 400
        
        if role not in organization['roles']:
            return json.dumps({"error": "Role not found in organization"}), 400        

        if permission is not None:
            permissionRoles=organization["acl"][permission]
            if role not in permissionRoles:
                return json.dumps({"error": "Role don't have the permission"}), 400  

            organizations_collection.update_one(
                {"name": session["organization"]},
                {"$pull": {f"acl.{permission}": role}}
            )
            message = {"message": f"Role {role} removed permission {permission} successfully"}
        if username is not None:
            if username not in organization["subjects"]: 
                return json.dumps({"error": "Username not found in organization"}), 400  
            roles = organization["subjects"][username]["roles"]
            if role not in roles:
                return json.dumps({"error": f"Role {role} was not found in subject"}), 400
            if role == MANAGER:
                counterManagers = 0
                subjects=organization["subjects"]
                for usernameSub,valueSub in subjects.items():
                    if MANAGER in valueSub["roles"] and valueSub["status"]=="up":
                        counterManagers += 1
                if counterManagers == 1:
                    return json.dumps({"error": "Rest only one manager error"}), 400  

            organizations_collection.update_one( 
                {"name": session["organization"]},
                {"$pull": {f"subjects.{username}.roles": role}}
            )
            message = {"message": f"Role {role} was removed from {username} successfully"}
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/document/acl", methods=["POST"])
def acl_doc():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, subject_public_key = decryptDataToDataWithSession(data)
        session = getSession(data.get("session"))
        if session is None:
            return json.dumps({"error": "Session not stored"}), 400
        
        doc_name = data.get("doc_name")
        signal = data.get("signal")
        role = data.get("role")
        permission = data.get("permission")
        
        if not conferDocSession(session, DOC_ACL,doc_name):
            return json.dumps({"error": "Session doesn't have the permission to modify ACL."}), 500

        document = documents_collection.find_one({"name": doc_name})
        if not document:
            return json.dumps({"error": "Document not found."}), 400


        if permission not in permissionListDOC:
            return json.dumps({"error": f"Permission {permission} not is not document ACL permission."}), 400
                
        if permission not in document["acl"]:
            return json.dumps({"error": f"Permission {permission} not found in document ACL."}), 400
        
        aclList = document["acl"]
        
        if signal == "+":
            if role in aclList.get(permission, []):
                return json.dumps({"error": f"Role {role} already has permission {permission}."}), 400
            aclList[permission].append(role)
        
        elif signal == "-":
            if role not in aclList.get(permission, []):
                return json.dumps({"error": f"Role {role} doesn't have permission {permission}."}), 400
            aclList[permission].remove(role)

        documents_collection.update_one(
            {"name": doc_name},
            {"$set": {"acl": aclList}}
        )

        message = {"message": f"Permission {permission} for role {role} updated successfully."}
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200

    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


def conferSession(session, permission):
    organization_name = session.get("organization")
    organization = organizations_collection.find_one({"name": organization_name})
    if not organization:
        return False
    
    aclInOrg = organization["acl"]
    roles_list = aclInOrg.get(permission,[])
    active_roles = {
        role for role, status in organization.get("roles", {}).items() if status == "up"
    }

    return any(role in roles_list and role in active_roles for role in session["roles"])


def conferDocSession(session, permission, doc_name):
    document = documents_collection.find_one({"name":doc_name})
    aclInDoc=document["acl"] if document else {}
    roles_list = aclInDoc.get(permission,[])

    organization_name = session.get("organization")
    organization = organizations_collection.find_one({"name": organization_name})
    if not organization:
        return False

    active_roles = {
        role for role, status in organization.get("roles", {}).items() if status == "up"
    }

    return any(role in roles_list and role in active_roles for role in session["roles"])


def getRoleInSessionWithDOC_NEW(session):
    if MANAGER in session["roles"]:
        return MANAGER
    organization_name = session.get("organization")
    organization = organizations_collection.find_one({"name": organization_name})
    aclInOrg = organization["acl"]
    roles_list = aclInOrg.get(DOC_NEW,[])
    for role in session["roles"]:
        if role in roles_list:
            return role
    return MANAGER


def encrypt(key, file_data):
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv)
    ).encryptor()

    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(file_data)
    digest.finalize().hex()
    return ciphertext, iv, tag


@app.route("/document/add", methods=["POST"])
def add_doc():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        data, subject_public_key = decryptDataToDataWithSession(data)

        session = getSession(data["session"])
        if session is None:
            return {"error":"session not stored"}, 400

        
        if not conferSession(session, DOC_NEW):
            return json.dumps({"error": "Session doesn't have the permission."}), 500

        doc_name = data.get("doc_name")
        file_data = data.get("file_data")
        if documents_collection.find_one({"name": doc_name}):
            return json.dumps({"error": "An exception occurred", "details": f"Document with name '{doc_name}' already exists."}), 500
        
        key = os.urandom(32)
        file_handle = sha256((doc_name+file_data).encode()).hexdigest()
        try:
            ciphertext, iv, tag = encrypt(key, file_data.encode())
        except:    
            return json.dumps({"error": "An exception occurred", "details": f"Encryption error"}), 500

        calculated_document_handle = sha256(doc_name.encode()).hexdigest()
        newRole = getRoleInSessionWithDOC_NEW(session)
        metadata = {
            "name": doc_name,
            "document_handle": calculated_document_handle,
            "create_date": datetime.datetime.now(),
            "creator": session["username"],
            "file_handle": file_handle,
            "acl": {DOC_ACL: list(set([MANAGER,newRole])),DOC_DELETE: list(set([MANAGER,newRole])),DOC_READ: list(set([MANAGER,newRole]))},
            "deleter": None,
        }
        metadataRestrict = {
            "name": doc_name,
            "document_handle": calculated_document_handle,
            "alg":"AES-GCM",
            "key":key.hex(),
            "iv":iv.hex(),
            "tag":tag.hex()
        }
        if not os.path.exists('files'):
            try:
                os.makedirs('files')
            except OSError as e:
                pass
        file_path = f"files/{file_handle}"
        with open(file_path, "wb") as f:
            f.write(ciphertext)

        documents_collection.insert_one(metadata)
        documents_private_collection.insert_one(metadataRestrict)

        organizations_collection.update_one(
            {"name": session["organization"]},
            {"$push": {"documents": doc_name}}
        )

        message={"message": "Document created successfully"}
        cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
        return json.dumps(cipherMessage), 200
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/document/remove", methods=["DELETE"])
def remove_doc():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        data, subject_public_key = decryptDataToDataWithSession(data)
        
        session = getSession(data.get("session"))
        if session is None:
            return {"error":"session not stored"}, 400
        doc_name = data.get("doc_name")
        havePermission = conferDocSession(session,DOC_DELETE,doc_name)
        document = documents_collection.find_one({"name":doc_name})
        if havePermission:
            if document["deleter"] is None:
                documents_collection.update_one({"name" : doc_name}, {"$set": {"deleter" : session["username"]}})
                documents_collection.update_one({"name" : doc_name}, {"$set": {"file_handle" : None}})

                message = {"message": "Document delete successfully"}
            else:
                message = {"message": "Document has already been deleted"}
            cipherMessage = encryptMessageWithSession(message, subject_public_key,session["session_id"])
            return json.dumps(cipherMessage), 200
        return json.dumps({"error": "An exception occurred", "details": "Session dont have the permission."}), 500
        
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/document/get_metadata", methods=["GET"])
def get_doc_metadata():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        data, subject_public_key = decryptDataToDataWithSession(data) 
        session=getSession(data.get("session"))
        if session is None:
            return {"error":"session not stored"}, 400

        doc_name = data.get("doc_name")
        havePermission = conferDocSession(session,DOC_READ,doc_name)
        if havePermission:
            document = documents_collection.find_one({"name":doc_name},{"_id":0})
            if document is None:
                return {"error":"Document not stored"}, 400
            document_private = documents_private_collection.find_one({"name":doc_name},{"_id":0})
            document["create_date"]=document["create_date"].isoformat()
            metadata = dict(document)
            metadata.update(dict(document_private))
            message={"message": "Document metadata get successfully","metadata":metadata}
            cipherMessage = encryptMessageWithSession(message,subject_public_key,session["session_id"]) 
            return json.dumps(cipherMessage), 200
        
        return json.dumps({"error": "An exception occurred", "details": "Session dont have the permission."}), 500
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


if __name__ == "__main__":
    print(f"Starting Repository on {host}:{port}")
    app.run(debug=True, host=host, port=int(port))