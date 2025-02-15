from flask import Flask, request
import json
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

DOC_ACL="DOC_ACL"
DOC_READ="DOC_READ"
DOC_DELETE="DOC_DELETE"
ROLE_ACL="ROLE_ACL"
SUBJECT_NEW="SUBJECT_NEW"
SUBJECT_DOWN="SUBJECT_DOWN"
SUBJECT_UP="SUBJECT_UP"
DOC_NEW="DOC_NEW"

app = Flask(__name__)

# Our Database
client = MongoClient("mongodb://mongodb:27017/")
db = client['repository']
# for collection_name in db.list_collection_names():
#     collection = db[collection_name]
#     collection.delete_many({}) 
organizations_collection = db['organizations']
sessions_collection = db['sessions']
documents_collection = db['documents']  # parte publica dos documentos
documents_private_collection = db['documents_private']  # parte privada dos documentos
subjects_collection = db['subjects']
localPass="sercurity pass2"
key_gen(b"localPass", REP_PUB_KEY)
repository_private_key, repository_public_key = key_load(b"localPass", REP_PUB_KEY)

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

        data, client_public_key = decryptDataToData(data)
        if data is None:
            if client_public_key == 3:
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
            "subjects": {username: {"status": "up", "public_key": public_key_file}},
            "documents": [],
            "acl": {DOC_ACL: ["Manager"], ROLE_ACL: ["Manager"], SUBJECT_NEW: ["Manager"], SUBJECT_DOWN: ["Manager"], SUBJECT_UP: ["Manager"], DOC_NEW: ["Manager"], DOC_READ: ["Manager"], DOC_DELETE: ["Manager"]},
            "public_key_file" : public_key_file
        }
        organizations_collection.insert_one(organization_data)

        message={"message": "Organization created successfully"}
        cipherMessage=encryptMessage(message, client_public_key)
        return json.dumps(cipherMessage), 200
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500


@app.route("/session/create", methods=["POST"])
def session_create():
    try:
        data = request.get_json()
        if not data:
            return json.dumps({"error": "No JSON data received"}), 400
        
        data, client_public_key = decryptDataToData(data)
        if data is None:
            if client_public_key == 3:
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
        cipherMessage=encryptMessage(message, client_public_key)
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

@app.route("/document/get_file", methods=["GET"])
def get_file():
    try:
        data = request.get_json()
        data, client_public_key = decryptDataToData(data)
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
        cipherMessage=encryptMessage(message, client_public_key)
        return json.dumps(cipherMessage), 200
    
    except Exception as e:
        return json.dumps({"error": "An exception occurred", "details": str(e)}), 500

@app.route("/role/assume", methods=["POST"])
def assume_role():
    # Second delivery
    # Implement HERE
    print("Executing: rep_assume_role")
    return "Role assumed"

@app.route("/role/drop", methods=["POST"])
def drop_role():
    # Second delivery
    # Implement HERE
    print("Executing: rep_drop_role")
    return "Role dropped"

@app.route("/role/list", methods=["GET"])
def list_roles():
    # Second delivery
    # Implement HERE
    print("Executing: rep_list_roles")
    return "Roles listed"

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

@app.route("/role/list_subjects", methods=["GET"])
def list_role_subjects():
    # Second delivery
    # Implement HERE
    print("Executing: rep_list_role_subjects")
    return "Role subjects listed"

@app.route("/subject/list_roles", methods=["GET"])
def list_subject_roles():
    # Second delivery
    # Implement HERE
    print("Executing: rep_list_subject_roles")
    return "Subject roles listed"

@app.route("/role/list_permissions", methods=["GET"])
def list_role_permissions():
    # Second delivery
    # Implement HERE
    print("Executing: rep_list_role_permissions")
    return "Role permissions listed"

@app.route("/permission/list_roles", methods=["GET"])
def list_permission_roles():
    # Second delivery
    # Implement HERE
    print("Executing: rep_list_permission_roles")
    return "Permission roles listed"

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
        
        subjects_collection.insert_one({
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
        counterManagers = 0
        subjects=organization["subjects"]
        for usernameSub,valueSub in subjects.items():
            if valueSub["status"]=="up":
                counterManagers += 1

        if counterManagers == 1:
            return json.dumps({"error": "The last subject cannot be suspend."}), 400  

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
    # Second delivery
    # Implement HERE
    print("Executing: rep_add_role")
    return "Role added"

@app.route("/role/suspend", methods=["POST"])
def suspend_role():
    # Second delivery
    # Implement HERE
    print("Executing: rep_suspend_role")
    return "Role suspended"

@app.route("/role/reactivate", methods=["POST"])
def reactivate_role():
    # Second delivery
    # Implement HERE
    print("Executing: rep_reactivate_role")
    return "Role reactivated"

@app.route("/permission/add", methods=["POST"])
def add_permission():
    # Second delivery
    # Implement HERE
    print("Executing: rep_add_permission")
    return "Permission added"

@app.route("/permission/remove", methods=["POST"])
def remove_permission():
    # Second delivery
    # Implement HERE
    print("Executing: rep_remove_permission")
    return "Permission removed"

def conferSession(session,permission):
    return True

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
        metadata = {
            "name": doc_name,
            "document_handle": calculated_document_handle,
            "create_date": datetime.datetime.now(),
            "creator": session["username"],
            "file_handle": file_handle,
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
        havePermission = conferSession(session,DOC_DELETE)
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
        havePermission = conferSession(session,DOC_READ)
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
    # print(f"Starting Repository on {REP_ADDRESS[0]}:{REP_ADDRESS[1]}")
    # app.run(debug=True, host=REP_ADDRESS[0], port=REP_ADDRESS[1])
    print(f"Starting Repository on {host}:{port}")
    app.run(debug=True, host=host, port=int(port))