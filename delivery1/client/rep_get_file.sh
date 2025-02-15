#!/bin/bash

# rep_get_file <file handle> [file]
if [ -z "$2" ]; then
  python3 ./client.py -c rep_get_file $1
else
  # If provided, call Python script with both arguments
  python3 ./client.py -c rep_get_file $1 $2
fi