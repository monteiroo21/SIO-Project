#!/bin/bash

# rep_remove_permission <session file> <role> <username>
# rep_remove_permission <session file> <role> <permission>
python3 ./client.py -c rep_remove_permission $@