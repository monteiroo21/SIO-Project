#!/bin/bash

# rep_activate_subject <session file> <username>
python3 ./client.py -c rep_activate_subject $@
exit_code=$?

if [ $exit_code -eq 0 ]; then
    echo "Success: Keys creatad."
elif [ $exit_code -gt 0 ]; then
    echo "Input Error: Invalid arguments or file missing."
else
    echo "Repository Error: Internal or server error occurred."
fi

exit $exit_code