#!/bin/bash

# rep_add_permission <session file> <role> <username>
# rep_add_permission <session file> <role> <permission>
python3 ./client.py -c rep_add_permission $@