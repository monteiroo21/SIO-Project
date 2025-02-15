# Project description

## Delivery 2

---

### **Delivery 2 Enhancements**

The second delivery builds upon the first with the addition of new functionalities, improvements, and bug fixes. The key updates include:

1. **Continuation from Delivery 1**:  
   - Delivery 2 retains the core functionalities implemented in Delivery 1 while enhancing them with robust session management, refined cryptographic implementations, and improved command execution.

2. **Bug Fixes**:  
   - Issues identified in the first delivery were addressed, particularly fixing commands that previously exhibited errors or inconsistencies.

---

### **How to test the program**
1. **In one terminal:**
   - Go to the delivery2/repository folder.
   - Run the command `docker-compose up --build` to initialize the server and the database.

2. **In another terminal:**
   - Go to the root folder of the project.
   - create a virtual environment with the command `python3 -m venv venv`.
   - Activate the virtual environment with the command `source venv/bin/activate`.
   - Install the required packages with the command `pip install -r requirements.txt`.
   - Go to the delivery2/client folder.
   - Give execution permissions:

```
chmod +x set_permissions.sh 
./set_permissions.sh
```

   - Run the bash commands files to test separate functions: (example: `./rep_list_orgs.sh`)
   - Or run a set of commands to test the overall behaviour: (`./test.sh`)
   

### **General Overview**
The system was developed to manage data securely and effectively. The functionalities include:
1. **Organization Management:** Creation and listing of organizations, associating users with organizations.
2. **User Management:** Adding, activating, suspending, and listing users within organizations. Each user has associated roles and public keys.
3. **Document Management:** Adding, listing, retrieving, encrypting, and removing documents.
4. **Session Management:** Secure session creation and validation for users within organizations. Sessions have time-based validity to enhance security.

---

### **Database**
The application uses **MongoDB** for data persistence, with the following collections:
- **`organizations`**: Stores organization details, including subjects (users), documents, and ACLs.
- **`sessions`**: Tracks active sessions, including validity timestamps.
- **`subjects`**: Maintains user details like roles, status, and public keys.
- **`documents`**: Manages metadata of documents stored securely on the server.

MongoDB's flexible schema supports the dynamic and hierarchical nature of the data, making it suitable for this use case.

---

### **Cryptography**

The application employs advanced cryptographic methods to secure communication and data, leveraging a hybrid approach that combines asymmetric and symmetric encryption:

1. **Elliptic Curve Cryptography (ECC):**
   - ECC is used to derive the symmetric encryption keys required for secure communication.  
   - The key derivation process involves two distinct key pairs: one private key from the client and one public key from the repository (or vice versa), utilizing the **ECDH (Elliptic Curve Diffie-Hellman)** protocol.  
   - This approach ensures the creation of a unique symmetric key for each session or transaction, enhancing overall security.

2. **Symmetric Cryptography (AES-GCM):**
   - The derived symmetric key is used for encrypting and decrypting messages between the client and the server.  
   - AES (Advanced Encryption Standard) in **GCM (Galois/Counter Mode)** ensures both confidentiality and data integrity by incorporating an **authentication tag** to detect potential tampering.  
   - The use of 256-bit keys guarantees a high level of encryption security.

3. **Key Derivation Process:**
   - The symmetric key derivation is implemented with **HKDF (HMAC-based Extract-and-Expand Key Derivation Function)**.  
   - **HKDF** utilizes the shared key generated through ECDH, combined with a random **salt**, to produce a robust and unique encryption key.  
   - This mechanism ensures that even with the same public/private key pairs, distinct symmetric keys can be generated for separate sessions.

4. **Digital Signatures and Verification:**
   - Messages are signed with the sender's private key using the **ECDSA (Elliptic Curve Digital Signature Algorithm)** to ensure authenticity and integrity.  
   - The recipient verifies the signature using the corresponding public key, validating the source and content of the message.

5. **Technical Implementation:**
   - Encryption Process:
     - Generate the symmetric key through ECDH and HKDF.
     - Encrypt messages using AES-GCM with a **nonce** (unique for each transaction).
   - Decryption Process:
     - Re-derive the symmetric key using the same public and private keys.
     - Decrypt messages securely with AES-GCM.

6. **Data Integrity:**
   - Data integrity is maintained using **SHA-256 hashes**, both during the signing and verification processes.  
   - Any tampering with the data is immediately detectable, ensuring the reliability and trustworthiness of the communication.

7. **Security Example:**
   - The encryption flow includes:
     - Exchange of public keys between the client and the server.
     - Derivation of a shared symmetric key using the exchanged keys.
     - Secure encryption and decryption of messages using AES-GCM and the derived key.

---

### **Security Features**
- **Session Validation:** Active sessions are validated against their expiration times, ensuring time-based access security.
- **Encryption and Decryption:** Sensitive data exchanged between the client and server is encrypted, ensuring confidentiality even in case of interception.

---

### **Authentication**

Authentication in the system is implemented to ensure secure user identification and access control. Key features include:

1. **User Validation:**
   - Each user is associated with a public-private key pair.
   - Authentication relies on validating the user's credentials against stored public keys within the repository.

2. **Password Encryption:**
   - Passwords are securely hashed or encrypted. In this implementation, passwords leverage the same encryption mechanism as the data messages, utilizing the client's key pair for encryption and decryption.
   - This approach prevents plaintext storage of sensitive information, enhancing security.

3. **Global Public Key Management:**
   - Each client securely provides a **global public key** during authentication.
   - This key is used to establish a trusted relationship between the client and the server, allowing secure data exchange.

4. **Session-Based Authentication:**
   - Each session is tied to a unique identifier and has a time-limited validity.
   - Session validation ensures that expired or unauthorized sessions cannot access the system, reducing risks of session hijacking.

5. **Access Control and Roles:**
   - Users are assigned roles with specific permissions defined in the **Access Control List (ACL)**.
   - Role-based access ensures that users only have the minimum permissions necessary for their tasks, following the principle of least privilege.

6. **Secure Command Execution:**
   - Commands require proper authentication to execute, ensuring that only authorized users can interact with the repository.

---

### **Commands Overview**

#### **1. Organization Management**
1. **`rep_create_org`**
   - **Description:** Creates a new organization in the repository.
   - **Parameters:**
     - `organization`: Name of the organization.
     - `username`: Name of the admin user.
     - `name`: Full name of the admin.
     - `email`: Email of the admin.
     - `public_key_file`: Path to the admin's public key file.
   - **Output:** Returns success or error response from the repository.

2. **`rep_list_orgs`**
   - **Description:** Lists all organizations stored in the repository.
   - **Output:** Outputs the list of organizations.

---

#### **2. Session Management**
1. **`rep_create_session`**
   - **Description:** Creates a session for a user within an organization.
   - **Parameters:**
     - `organization_name`: Organization name.
     - `username`: Username of the user.
     - `password`: Password associated with the credentials file.
     - `credentials_file`: Path to the credentials file. 
         - These credentials must be the same as those used to create the subject with this username.
     - `session_file`: Path to save the session ID.
   - **Output:** Establishes a session and saves session credentials.

2. **`rep_list_subjects`**
   - **Description:** Lists all subjects (users) in an organization.
   - **Parameters:**
     - `session_file`: Session file path.
     - `username` *(optional)*: Filter results by username.

---

#### **3. User Management**
1. **`rep_add_subject`**
   - **Description:** Adds a new user to the organization.
   - **Parameters:**
     - `session_file`: Path to the session file.
     - `username`: Username for the new subject.
     - `name`: Full name of the user.
     - `email`: Email address of the user.
     - `public_key_file`: Path to the public key file.
   - **Output:** Adds the user and associates them with the organization.

2. **`rep_suspend_subject` / `rep_activate_subject`**
   - **Description:** Suspend or activate a user.
   - **Parameters:**
     - `session_file`: Path to the session file.
     - `username`: Username of the subject to be suspended/activated.

---

#### **4. Document Management**
1. **`rep_add_doc`**
   - **Description:** Adds a document to the repository.
   - **Parameters:**
     - `session_file`: Session file path.
     - `doc_name`: Name of the document.
     - `file_name`: Path to the document file.
   - **Output:** Encrypts and uploads the document to the repository.

2. **`rep_get_doc_metadata`**
   - **Description:** Retrieves metadata of a document. 
   - **Parameters:**
     - `session_file`: Path to the session file.
     - `doc_name`: Name of the document.
   - **Output:** Returns document metadata.

3. **`rep_get_doc_file`**
   - **Description:** Downloads and decrypts a document.
   - **Parameters:**
     - `session_file`: Path to the session file.
     - `doc_name`: Name of the document.
     - `file_name` *(optional)*: Path to save the document file.

4. **`rep_delete_doc`**
   - **Description:** Deletes a document from the repository.
   - **Parameters:**
     - `session_file`: Path to the session file.
     - `doc_name`: Name of the document to delete.

---

#### **5. Role & Permission Management**
1. **`rep_add_role` / `rep_suspend_role` / `rep_reactivate_role`**
   - **Description:** Adds, suspends, or reactivates a role within an organization.
   - **Parameters:**
     - `session_file`: Path to the session file.
     - `role`: Name of the role.

2. **`rep_add_permission` / `rep_remove_permission`**
   - **Description:** Adds or removes a permission for a role.
   - **Parameters:**
     - `session_file`: Path to the session file.
     - `role`: Role to update.
     - `permission`: Permission to add/remove.

3. **`rep_list_roles`**
   - **Description:** Lists all roles in the organization.

4. **`rep_acl_doc`**
   - **Description:** Updates access control for a document.
   - **Parameters:**
     - `session_file`: Path to the session file.
     - `doc_name`: Name of the document.
     - `signal`: `+` to add, `-` to remove.
     - `role`: Role to associate with the permission.
     - `permission`: Permission to grant/revoke.

---

### **Message Numbers and Security: Key Points**

1. **Purpose**: 
   - Ensure **message order** and **uniqueness** within a session.
   - Protect against **replay attacks** and verify message **freshness**.

2. **Security Benefits**:
   - **Replay Protection**: Prevents re-sending of intercepted messages.
   - **Integrity and Authenticity**: Validates message sequence and source via encryption and signatures.
   - **Order Enforcement**: Guarantees operations are processed in the correct sequence.

3. **Implementation**:
   - Each session starts with message number `0`, incremented with every new message.
   - Repository validates numbers to reject replayed, out-of-sequence, or tampered messages.

4. **Integration**:
   - Message numbers are included in **encryption**, **signatures**, and **digest**, ensuring tampering is detectable.

5. **Impact**:
   - Strengthens **session security** against manipulation, impersonation, and replay attacks.
   - Maintains system **reliability** and **logical consistency**.

---

### **Session Robustness**

To ensure robust and secure sessions, the implementation addresses the following potential attacks:

1. **Eavesdropping**:  
   - **Mitigation**: All data exchanged between the client and repository is encrypted using **AES-GCM** for symmetric encryption and **ECC** for key exchange. This ensures that sensitive information remains confidential even if intercepted by a third party.

2. **Impersonation**:  
   - **Mitigation**: Authentication is enforced through the validation of user credentials using private-public key pairs. The repository verifies signatures created with the client's private key against its corresponding public key. This ensures that only authorized users can initiate and maintain sessions.

3. **Manipulation**:  
   - **Mitigation**: Messages are secured with integrity controls using the **authentication tag** generated by AES-GCM and **digital signatures**. These mechanisms detect and prevent any unauthorized modification of the data during transit.

4. **Replay**:  
   - **Mitigation**: The use of **message numbers** ensures that each message within a session is unique and processed in sequence. The repository rejects any message that is out of order, already processed, or duplicated. This prevents attackers from reusing valid messages to impersonate or manipulate sessions.

---

### **Session Lifetime**

1. **Time-Limited Validity**:  
   - Sessions are created with a predefined expiration time of 1 hour. After this period, any interaction attempts are rejected unless a new session is established. This reduces the risk of unauthorized access from inactive or abandoned sessions.

2. **Inactivity Timeout**:  
   - Sessions are automatically deleted after a period of inactivity. This ensures that unused sessions do not remain active indefinitely, further mitigating potential security vulnerabilities.

---

## How to Delete Data from the Database

To completely remove the data stored in the database, follow the steps below:

### Step 1: Navigate to the Configuration Folder
1. Open a terminal.
2. Change the directory to the configuration folder using the command:
   ```bash
   cd ~/.sio
   ```

### Step 2: Delete the State File
1. Locate and remove the `state.json` file, which holds the current state of the repository.
2. Run the command:
   ```bash
   rm state.json
   ```

### Step 3: Modify `repository.py` for Data Deletion
1. Open the `repository.py` file in an editor.
2. Uncomment the following lines of code:
   ```python
   for collection_name in db.list_collection_names():
       collection = db[collection_name]
       collection.delete_many({})
   ```
   These lines will iterate through all collections in the database and delete their contents.

### Step 4: Rebuild and Start the Docker Container
1. Return to the `delivery2/repository` folder.
2. Run the command to rebuild and start the Docker containers:
   ```bash
   docker-compose up --build
   ```
   This will clear the database contents during the container initialization.

### Step 5: Revert Changes in `repository.py`
1. After verifying that the data has been deleted, go back to the `repository.py` file.
2. Comment out the same lines of code to disable the deletion functionality:
   ```python
   # for collection_name in db.list_collection_names():
   #     collection = db[collection_name]
   #     collection.delete_many({})
   ```

### Step 6: Rebuild and Start the Docker Container Again
1. Run the `docker-compose up --build` command once more to finalize the changes:
   ```bash
   docker-compose up --build
   ```

At this point, the database will have been reset, and the system is ready for new data to be added and tested.

---

#### **Notes**

**Implementation of `ROLE_ACL`**:  
   - The **`ROLE_ACL`** feature was implemented, but due to interpretational uncertainties in the project requirements, it is unclear if the implementation fully aligns with the expected behavior. Further clarification or testing may be required to validate its compliance with the specification.

2. **Repository Error Codes**:  
   - It is important to note that errors originating from the repository during testing are returned as **code 255** instead of a negative number.

