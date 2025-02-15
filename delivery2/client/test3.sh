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
        eval "python3 client.py -c clear"
        exit 1
    else
        echo "Test passed: $cmd"
    fi
    echo "--------------------------"
    echo ""
}

# Tests for ./rep_subject_credentials
check_command "./rep_subject_credentials.sh pass1 -v -k "../repository/credential_file" -r "0.0.0.0:6000"" 1
check_command "./rep_subject_credentials.sh passA credA.pem -v -k "../repository/credential_file" -r "0.0.0.0:6000"" 0
check_command "./rep_subject_credentials.sh passB credB.pem -k "../repository/credential_file" -r "0.0.0.0:6000"" 0
check_command "./rep_subject_credentials.sh pass1 cred1.pem -k "../repository/credential_file" -r "0.0.0.0:6000"" 0
check_command "./rep_subject_credentials.sh pass2 cred2.pem -k "../repository/credential_file" -r "0.0.0.0:6000"" 0
check_command "./rep_subject_credentials.sh pass3 cred3.pem -k "../repository/credential_file" -r "0.0.0.0:6000"" 0
check_command "./rep_subject_credentials.sh pass4 cred4.pem -k "../repository/credential_file" -r "0.0.0.0:6000"" 0


# Tests for ./rep_create_org
check_command "./rep_create_org.sh org1 user1 Name email@domain.com InvalidCredentials -r "0.0.0.0:6000"" 1
check_command "./rep_create_org.sh InvalidOrg user1 -r "0.0.0.0:6000"" 1
check_command "./rep_create_org.sh orgA userA NameA emailA@domain.com credA.pem -r "0.0.0.0:6000"" 0
check_command "./rep_create_org.sh orgB userB NameB emailB@domain.com credB.pem -r "0.0.0.0:6000"" 0
check_command "./rep_create_org.sh orgA userA NameA emailA@domain.com credA.pem -r "0.0.0.0:6000"" 255

# Tests for ./rep_list_orgs
check_command "./rep_list_orgs.sh -r "0.0.0.0:6000"" 0

# Tests for ./rep_create_session
check_command "./rep_create_session.sh orgA userA passA credA.pem sessaoA -r "0.0.0.0:6000"" 0
check_command "./rep_create_session.sh orgB userB passB credB.pem sessaoB -r "0.0.0.0:6000"" 0
check_command "./rep_create_session.sh orgA userB passA credA.pem sessaoA -r "0.0.0.0:6000"" 255

# Tests for ./rep_assume_role
check_command "./rep_assume_role.sh sessaoA Manager -r "0.0.0.0:6000"" 0
check_command "./rep_assume_role.sh sessaoA Manager -r "0.0.0.0:6000"" 255
check_command "./rep_assume_role.sh sessaoB Manager -r "0.0.0.0:6000"" 0


# Tests for ./rep_add_subject
check_command "./rep_add_subject.sh sessaoA user1 name1 email1@domain.com cred1.pem -r "0.0.0.0:6000"" 0
check_command "./rep_add_subject.sh sessaoA user2 name2 email2@domain.com cred2.pem -r "0.0.0.0:6000"" 0
check_command "./rep_add_subject.sh sessaoB user3 name3 email3@domain.com cred3.pem -r "0.0.0.0:6000"" 0
check_command "./rep_add_subject.sh sessaoB user4 name4 email4@domain.com cred4.pem -r "0.0.0.0:6000"" 0

# Tests for ./rep_add_role
check_command "./rep_add_role.sh sessao Editor -r "0.0.0.0:6000"" 2
check_command "./rep_add_role.sh sessao2 Editor -r "0.0.0.0:6000"" 255
check_command "./rep_add_role.sh sessaoA Editor -r "0.0.0.0:6000"" 0
check_command "./rep_add_role.sh sessaoB Gestor -r "0.0.0.0:6000"" 0

# Tests for ./rep_add_permission
check_command "./rep_add_permission.sh sessaoA Editor user1 -r "0.0.0.0:6000"" 0
check_command "./rep_add_permission.sh sessaoB Gestor user3 -r "0.0.0.0:6000"" 0
check_command "./rep_add_permission.sh sessaoA Editor DOC_NEW -r "0.0.0.0:6000"" 0
check_command "./rep_add_permission.sh sessaoA Editor ROLE_UP -r "0.0.0.0:6000"" 0
check_command "./rep_add_permission.sh sessaoA Editor SUBJECT_NEW -r "0.0.0.0:6000"" 0
check_command "./rep_add_permission.sh sessaoB Gestor SUBJECT_NEW -r "0.0.0.0:6000"" 0
check_command "./rep_add_permission.sh sessaoB Gestor SUBJECT_DOWN -r "0.0.0.0:6000"" 0

# Tests for ./rep_assume_role
check_command "./rep_assume_role.sh sessao1 Editor -r "0.0.0.0:6000"" 0
check_command "./rep_assume_role.sh sessao3 Gestor -r "0.0.0.0:6000"" 0

# Tests for ./rep_get_doc_metadata
check_command "./rep_add_doc.sh sessaoA Doc1 ../file.txt -r "0.0.0.0:6000"" 0
check_command "./rep_add_doc.sh sessaoA Doc2 ../eula.txt -r "0.0.0.0:6000"" 0
check_command "./rep_get_doc_metadata.sh sessaoA Doc1 -r "0.0.0.0:6000"" 0
check_command "./rep_get_doc_metadata.sh sessaoA Doc2 -r "0.0.0.0:6000"" 0