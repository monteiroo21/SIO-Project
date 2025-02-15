#!/bin/bash

# Loop through all .sh files in the current directory
for file in *.sh; do
    # Check if the file is not this script itself
    if [[ "$file" != "set_permissions.sh" ]]; then
        # Give execute permissions
        chmod +x "$file"
        echo "Permissions added to: $file"
    fi
done