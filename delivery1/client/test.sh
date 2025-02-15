#!/bin/bash

# Function to execute and check each command
check_command() {
    local cmd="$1"
    local expected="$2"
    echo "Running: $cmd"
    eval "$cmd"
    local result=$?
    if [ $result -ne $expected ]; then
        echo "Test failed: $cmd (Expected: $expected, Got: $result)"
    else
        echo "Test passed: $cmd"
    fi
    echo "--------------------------"
    echo ""
}

# Test cases for main commands
check_command "./rep_subject_credentials.sh passA credA.pem" 0
check_command "./rep_subject_credentials.sh passA cred1.pem" 0
check_command "./rep_create_org.sh orgA userA NameA emailA@domain.com credA.pem" 0
check_command "./rep_list_orgs.sh" 0
check_command "./rep_create_session.sh orgA userA passA credA.pem sessionA" 0
check_command "./rep_add_doc.sh sessionA Doc1 ../file.txt" 0
check_command "./rep_get_doc_metadata.sh sessionA Doc1" 0
check_command "./rep_list_docs.sh sessionA" 0
check_command "./rep_get_doc_file.sh sessionA Doc1 output2.txt" 0
check_command "./rep_delete_doc.sh sessionA Doc1" 0
check_command "./rep_list_subjects.sh sessionA" 0
check_command "./rep_add_subject.sh sessionA user1 name1 email1@domain.com cred1.pem" 0
check_command "./rep_suspend_subject.sh sessionA user1" 0
check_command "./rep_activate_subject.sh sessionA user1" 0
check_command "./rep_get_file.sh e8bdc0b7931ae7629cab33efbae01cf86145d692b6a244c6025029e36281d920 output.txt" 0
check_command "./rep_decrypt_file.sh output.txt" 0
check_command "./rep_get_doc_metadata.sh sessionA Doc2" 255
check_command "./rep_get_doc_file.sh sessionA Doc1 output2.txt" 1
echo "All tests completed."
