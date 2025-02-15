#!/bin/bash

# rep_get_doc_file <session file> <document name> [file]
if [ -z "$3" ]; then
  python3 ./client.py -c rep_get_doc_file $1 $2
else
  python3 ./client.py -c rep_get_doc_file $1 $2 $3
fi