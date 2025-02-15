#!/bin/bash

# rep_list_subjects <session file> [username]
if [ -z "$2" ]; then
  python3 ./client.py -c rep_list_subjects $1
else
  python3 ./client.py -c rep_list_subjects $1 $2
fi