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
run_command() {
    local cmd="$1"
    echo "Running: $cmd"
    eval "$cmd"
    echo "--------------------------"
}

# Execute commands and print outputs
run_command "./rep_subject_credentials.sh pass KEYS/key1.pem"
run_command "./rep_create_org.sh NovaOrg NovoUser NovoUser pass KEYS/key1.pem"
run_command "./rep_list_orgs.sh"
run_command "./rep_create_session.sh NovaOrg NovoUser pass KEYS/key1.pem logs"
run_command "./rep_add_subject.sh logs novonovonome nome1 email2 KEYS/key1.pem"
run_command "./rep_list_subjects.sh logs"
run_command "./rep_suspend_subject.sh logs novonovonome"
run_command "./rep_activate_subject.sh logs novonovonome"
run_command "./rep_add_doc.sh logs aaa ../file.txt"
run_command "./rep_get_doc_metadata.sh logs aaa"
run_command "./rep_get_doc_file.sh logs aaa get_doc_file.txt"
# run_command "./rep_decrypt_file.sh $TEST_ENCRYPTED_FILE $TEST_METADATA"
run_command "./rep_list_docs.sh logs"
# run_command "./rep_get_file.sh $SESSION_FILE $TEST_USERNAME $TEST_DOC_NAME $TEST_OUTPUT_FILE"
run_command "./rep_delete_doc.sh logs aaa"
run_command "./rep_list_docs.sh logs"

echo "All commands executed."