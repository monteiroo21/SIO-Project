# Project description

## Delivery 1

### **How to test the program**
1. **In one terminal:**
   - Go to the delivery1/repository folder.
   - Run the command `docker-compose up --build` to initialize the server and the database.

2. **In another terminal:**
   - Go to the root folder of the project.
   - create a virtual environment with the command `python3 -m venv venv`.
   - Activate the virtual environment with the command `source venv/bin/activate`.
   - Install the required packages with the command `pip install -r requirements.txt`.
   - Go to the delivery1/client folder.
   - Give execution permissions:
         ```
         chmod +x set_permissions.sh 
         ./set_permissions.sh
         ```
   - Run the bash commands files. (example: `./rep_list_orgs.sh`)
   - Or run a set of commands (./test_commands.sh)

## Important notes: In the event of an error while reading the global public key file for the client in the repository, it is necessary to remove the "id_client" field from the *state.json* file.

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
The application uses robust cryptographic algorithms to secure communication and data:
1. **Asymmetric Cryptography (EC - Elliptic Curve):**
   - Utilized for generating and managing public-private key pairs.
   - Ensures secure exchange of data between the client and the server.
   - Elliptic Curve cryptography is lightweight and efficient, making it ideal for scenarios requiring high security with low computational overhead.

2. **Symmetric Cryptography (AES-GCM):**
   - Used to encrypt files and sensitive data.
   - AES (Advanced Encryption Standard) in **GCM (Galois/Counter Mode)** provides both encryption and integrity verification via an authentication tag.
   - The 256-bit key ensures high levels of security.

3. **Key Management:**
   - Keys are securely generated and stored using cryptographic libraries.
   - The system ensures secure exchange of the client’s global public key with the repository, enabling trusted communication.

4. **Data Integrity:**
   - A **SHA-256 hash** is used to verify the integrity of files and data, while using the ECC. This ensures that any tampering with encrypted data can be detected.

---

### **Security Features**
- **Session Validation:** Active sessions are validated against their expiration times, ensuring time-based access security.
- **Encryption and Decryption:** Sensitive data exchanged between the client and server is encrypted, ensuring confidentiality even in case of interception.

---

### **Todo for the next delivery**
1. **Implement the session file:** currently the state session is stored in the state file, instead of the session file.