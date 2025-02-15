#!/bin/bash

# Define test arguments
TEST_PASSWORD="test_password"
TEST_CREDENTIALS="test_credentials.txt"
TEST_ORGANIZATION="test_org"
TEST_USERNAME="test_user"
TEST_NAME="Test User"
TEST_EMAIL="test_user@example.com"
TEST_PUBLIC_KEY="test_public_key.pem"
SESSION_FILE="test_session.json"
TEST_DOC_NAME="test_doc"
TEST_ENCRYPTED_FILE="test_encrypted.bin"
TEST_METADATA="test_metadata.json"
TEST_OUTPUT_FILE="test_output.txt"

# Function to execute and print each command
int=0
run_command() {
    echo "$int"
    local cmd="$1"
    echo "Running: $cmd"
    eval "$cmd"
    echo "--------------------------"
    echo ""
    echo ""
    int=$((int+1))
}

# Execute commands and print outputs

# 0. Subject Credentials
run_command "./rep_subject_credentials.sh pass key.pem"

# 1. Organization Management
run_command "./rep_create_org.sh NovaOrg2 NovoUser NovoUser pass key.pem"
run_command "./rep_list_orgs.sh"
run_command "./rep_create_org.sh NovaOrg2 NovoUser NovoUser pass key.pem"  # Should fail

# 2. Session Management
run_command "./rep_create_session.sh NovaOrg2 NovoUser pass key.pem logs"
run_command "./rep_assume_role.sh logs Manager"

# 3. Subject Management
run_command "./rep_add_subject.sh logs novonovonome nome12 email2 key.pem"
run_command "./rep_add_subject.sh logs Carlos Calrlos email2 key.pem"
run_command "./rep_list_subjects.sh logs"
run_command "./rep_suspend_subject.sh logs novonovonome"
run_command "./rep_suspend_subject.sh logs novonovonome"  # Should fail
run_command "./rep_list_subjects.sh logs"
run_command "./rep_activate_subject.sh logs novonovonome"
run_command "./rep_activate_subject.sh logs novonovonome" # Should fail

# 4. Role Management
run_command "./rep_add_role.sh logs Manager2"
run_command "./rep_reactivate_role.sh logs Manager2"   # Should fail
run_command "./rep_suspend_role.sh logs Manager2"
run_command "./rep_suspend_role.sh logs Manager2"   # Should fail
run_command "./rep_reactivate_role.sh logs Manager2"

# 5. Permission Management
run_command "./rep_add_permission.sh logs Manager2 novonovonome"
run_command "./rep_reactivate_role.sh logs Manager2"
run_command "./rep_reactivate_role.sh logs Manager2"
run_command "./rep_add_permission.sh logs Manager novonovonome"
run_command "./rep_remove_permission.sh logs Manager2 novonovonome"

# 6. Document Management
run_command "./rep_add_doc.sh logs aaa ../file.txt"
run_command "./rep_get_doc_metadata.sh logs aaa"
run_command "./rep_get_doc_file.sh logs aaa get_doc_file.txt"
run_command "./rep_get_file.sh 3895fb67238603e28cad859dee952fd6b8081376de354fb4530732cb5ca27a28"
run_command "./rep_get_file.sh 3895fb67238603e28cad859dee952fd6b8081376de354fb4530732cb5ca27a28 newFile"
run_command "./rep_list_docs.sh logs"
run_command "./rep_delete_doc.sh logs aaa"
run_command "./rep_list_docs.sh logs"

# 7.
run_command "./rep_list_roles.sh logs"
run_command "./rep_list_role_subjects.sh logs Manager"
run_command "./rep_list_subject_roles.sh logs novonovonome"
run_command "./rep_list_role_permissions.sh logs Manager"
# run_command "./rep_list_permission_roles.sh logs DOC_DELETE"

# 8. Document Encryption
run_command "./rep_decrypt_file.sh newFile '{\"key\": \"ad1730f90c0049634b85493025ebdc2d044c55624c1b9fc48ae8ee2c7c72efde\", \"alg\": \"AES\", \"iv\": \"7817abea4e9b6cb19d51928a\", \"tag\": \"99f818dcc32b3ec4580f7a442c30761f\"}'"


# 9. Second Role Management
run_command "./rep_list_roles.sh logs"
run_command "./rep_drop_role.sh logs Manager"
run_command "./rep_list_roles.sh logs"

echo "All commands executed."