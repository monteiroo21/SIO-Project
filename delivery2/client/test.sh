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

# Tests for ./rep_subject_credentials
check_command "./rep_subject_credentials.sh pass1 -v" 1
check_command "./rep_subject_credentials.sh passA credA.pem -v" 0
check_command "./rep_subject_credentials.sh passB credB.pem" 0
check_command "./rep_subject_credentials.sh pass1 cred1.pem" 0
check_command "./rep_subject_credentials.sh pass2 cred2.pem" 0
check_command "./rep_subject_credentials.sh pass3 cred3.pem" 0
check_command "./rep_subject_credentials.sh pass4 cred4.pem" 0

# Tests for ./rep_create_org
check_command "./rep_create_org.sh org1 user1 Name email@domain.com InvalidCredentials" 1
check_command "./rep_create_org.sh InvalidOrg user1" 1
check_command "./rep_create_org.sh orgA userA NameA emailA@domain.com credA.pem" 0
check_command "./rep_create_org.sh orgB userB NameB emailB@domain.com credB.pem" 0
check_command "./rep_create_org.sh orgA userA NameA emailA@domain.com credA.pem" 255

# Tests for ./rep_list_orgs
check_command "./rep_list_orgs.sh" 0

# Tests for ./rep_create_session
check_command "./rep_create_session.sh orgA userA passA credA.pem sessaoA" 0
check_command "./rep_create_session.sh orgB userB passB credB.pem sessaoB" 0
check_command "./rep_create_session.sh orgA userB passA credA.pem sessaoA" 255

# Tests for ./rep_assume_role
check_command "./rep_assume_role.sh sessaoA Manager" 0
check_command "./rep_assume_role.sh sessaoA Manager" 255
check_command "./rep_assume_role.sh sessaoB Manager" 0


# Tests for ./rep_add_subject
check_command "./rep_add_subject.sh sessaoA user1 name1 email1@domain.com cred1.pem" 0
check_command "./rep_add_subject.sh sessaoA user2 name2 email2@domain.com cred2.pem" 0
check_command "./rep_add_subject.sh sessaoB user3 name3 email3@domain.com cred3.pem" 0
check_command "./rep_add_subject.sh sessaoB user4 name4 email4@domain.com cred4.pem" 0

# Tests for additional sessions
check_command "./rep_create_session.sh orgA user1 pass1 cred1.pem sessao1" 0
check_command "./rep_create_session.sh orgA user2 pass2 cred2.pem sessao2" 0
check_command "./rep_create_session.sh orgB user3 pass3 cred3.pem sessao3" 0
check_command "./rep_create_session.sh orgB user4 pass4 cred4.pem sessao4" 0

# Tests for ./rep_list_subjects
check_command "./rep_list_subjects.sh sessaoA" 0
check_command "./rep_list_subjects.sh sessaoA user1" 0
check_command "./rep_list_subjects.sh sessaoA user2" 0

# Tests for ./rep_add_role
check_command "./rep_add_role.sh sessao Editor" 2
check_command "./rep_add_role.sh sessao2 Editor" 255
check_command "./rep_add_role.sh sessaoA Editor" 0
check_command "./rep_add_role.sh sessaoB Gestor" 0

# Tests for ./rep_list_roles
check_command "./rep_list_roles.sh sessaoA" 0
check_command "./rep_list_roles.sh sessaoB" 0

# Tests for ./rep_add_permission
check_command "./rep_add_permission.sh sessaoA Editor user1" 0
check_command "./rep_add_permission.sh sessaoB Gestor user3" 0
check_command "./rep_add_permission.sh sessaoA Editor DOC_NEW" 0
check_command "./rep_add_permission.sh sessaoA Editor ROLE_UP" 0
check_command "./rep_add_permission.sh sessaoA Editor SUBJECT_NEW" 0
check_command "./rep_add_permission.sh sessaoB Gestor SUBJECT_NEW" 0
check_command "./rep_add_permission.sh sessaoB Gestor SUBJECT_DOWN" 0
check_command "./rep_add_permission.sh sessaoB Gestor ROLE_DOWN" 0
check_command "./rep_add_permission.sh sessaoB Gestor ROLE_UP" 0

# Tests for ./rep_remove_permission
check_command "./rep_remove_permission.sh sessaoA Editor DOC_NEW" 0
check_command "./rep_add_permission.sh sessaoA Editor DOC_NEW" 0

# Tests for ./rep_assume_role
check_command "./rep_assume_role.sh sessao1 Editor" 0
check_command "./rep_assume_role.sh sessao3 Gestor" 0

# Tests for ./rep_list_role_permissions
check_command "./rep_list_role_permissions.sh sessaoA Editor" 0
check_command "./rep_list_role_permissions.sh sessaoB Gestor" 0

# Tests for ./rep_list_permission_roles
check_command "./rep_list_permission_roles.sh sessaoA DOC_NEW" 0

# Tests for ./rep_get_doc_metadata
check_command "./rep_add_doc.sh sessaoA Doc1 ../file.txt" 0
check_command "./rep_add_doc.sh sessaoA Doc2 ../eula.txt" 0
check_command "./rep_get_doc_metadata.sh sessaoA Doc1" 0
check_command "./rep_get_doc_metadata.sh sessaoA Doc2" 0

# Tests for ./rep_list_docs
check_command "./rep_list_docs.sh sessao2" 0
check_command "./rep_list_docs.sh sessaoA" 0
check_command "./rep_list_docs.sh sessaoA -s user1" 0
check_command "./rep_list_docs.sh sessaoA -s user2 -d nt 01-01-2024" 0
check_command "./rep_list_docs.sh sessaoA -d et 01-01-2024" 0

# Tests for ./rep_acl_doc
check_command "./rep_acl_doc.sh sessaoA Doc2 + Editor DOC_DELETE" 0
check_command "./rep_acl_doc.sh sessaoA Doc2 + Editor DOC_READ" 0

check_command "./rep_get_doc_file.sh sessao1 Doc2 output1.txt" 0

# Tests for ./rep_delete_doc
check_command "./rep_delete_doc.sh sessao" 1
check_command "./rep_delete_doc.sh sessao1 novo_document_name" 255
check_command "./rep_delete_doc.sh sessao2 Doc1" 255
check_command "./rep_delete_doc.sh sessaoA Doc2" 0
check_command "./rep_list_docs.sh sessaoA" 0

# Tests for ./rep_get_file
check_command "./rep_get_file.sh 22a7fa5533cd7d0c9e982c0a062cf5ed584ad8d5d83683f27be8677568d2f219 output.txt" 0

# Tests for ./rep_list_role_permissions
check_command "./rep_list_role_permissions.sh sessaoA Editor" 0
check_command "./rep_list_role_permissions.sh sessaoB Gestor" 0

# Tests for ./rep_decrypt_file
check_command "./rep_decrypt_file.sh file.txt" 1
check_command "./rep_decrypt_file.sh output.txt" 0

check_command "./rep_add_doc.sh sessao1 Doc3 ../file.txt" 0
check_command "./rep_get_doc_file.sh sessao1 Doc3 output2.txt" 0

check_command "./rep_list_subjects.sh  sessaoB" 0
check_command "./rep_suspend_subject.sh  sessaoB user4" 0
check_command "./rep_create_session.sh orgB user4 pass4 cred4.pem sessao4" 255
check_command "./rep_activate_subject.sh  sessaoB user4" 0
check_command "./rep_create_session.sh orgB user4 pass4 cred4.pem sessao4" 0
check_command "./rep_suspend_subject.sh  sessaoB user4" 0
check_command "./rep_list_subjects.sh  sessao4" 255


check_command "./rep_list_role_permissions.sh sessaoA Editor" 0
check_command "./rep_list_role_subjects.sh sessaoB Gestor" 0
check_command "./rep_list_subject_roles.sh sessaoB user3" 0
check_command "./rep_list_role_permissions.sh sessaoB Gestor" 0
check_command "./rep_list_permission_roles.sh sessaoB DOC_NEW" 0

check_command "./rep_suspend_role.sh sessao3 Gestor" 0
check_command "./rep_assume_role.sh sessao3 Gestor" 255
check_command "./rep_activate_subject.sh  sessaoB user4" 0

check_command "./rep_add_permission.sh sessaoB Gestor user4" 255
check_command "./rep_assume_role.sh sessao4 Gestor" 255

check_command "./rep_add_subject.sh sessao3 user5 name5 email5@domain.com cred4.pem" 255

check_command "./rep_reactivate_role.sh sessao3 Gestor" 255
check_command "./rep_reactivate_role.sh sessaoB Gestor" 0
check_command "./rep_add_subject.sh sessao3 user6 name6 email1@domain.com cred1.pem" 0
check_command "./rep_drop_role.sh sessao3 Gestor" 0
check_command "./rep_add_subject.sh sessao3 user7 name7 email1@domain.com cred1.pem" 255

check_command "./rep_remove_permission.sh sessaoA Editor DOC_NEW" 0

check_command "./rep_list_role_permissions.sh sessaoA Editor | grep 'DOC_NEW'" 1
check_command "./rep_remove_permission.sh sessaoB Gestor ROLE_DOWN" 0
check_command "./rep_remove_permission.sh sessaoB NonExistentRole DOC_DELETE" 255
check_command "./rep_remove_permission.sh sessaoA Editor SUBJECT_NEW" 0
check_command "./rep_acl_doc.sh sessaoA Doc2 - Editor DOC_READ" 0
check_command "./rep_acl_doc.sh sessaoA Doc2 + Editor DOC_READ" 0

echo "All commands executed."
