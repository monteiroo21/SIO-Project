#!/bin/bash

# rep_list_docs <session file> [-s username] [-d nt/ot/et date]
SESSION_FILE=$1

shift

python3 ./client.py -c rep_list_docs "$SESSION_FILE" "$@"