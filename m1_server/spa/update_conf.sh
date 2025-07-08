#!/bin/bash

# update_conf.sh - Removes expired entries from access_ah.conf

CONFIG_FILE="/path/to/access_ah.conf" # Use absolute path for cron
LOCK_FILE="/tmp/access_ah.lock"
TEMP_FILE=$(mktemp)

# Get current time as Unix timestamp
NOW=$(date +%s)

echo "[$(date)] Running AH config cleanup..."

# Use flock for simple locking (install flock if needed)
(
  flock -x 200 # Acquire exclusive lock on fd 200

  if [ ! -f "$CONFIG_FILE" ]; then
    echo "Config file $CONFIG_FILE not found. Exiting."
    exit 0
  fi

  # Process the file line by line, keeping only valid stanzas
  in_stanza=0
  keep_stanza=0
  current_expiry=0
  stanza_content=""

  while IFS= read -r line || [ -n "$line" ]; do
    trimmed_line=$(echo "$line" | sed 's/^[ \t]*//;s/[ \t]*$//') # Trim whitespace

    # Skip blank/comment lines
    if [[ -z "$trimmed_line" || "$trimmed_line" =~ ^# ]]; then
        echo "$line" >> "$TEMP_FILE" # Keep comments/blanks in output
        continue
    fi

    # Start of stanza?
    if [[ "$trimmed_line" =~ ^\[.+\]$ ]]; then
        # Process the previous stanza before starting new one
        if [ "$in_stanza" -eq 1 ] && [ "$keep_stanza" -eq 1 ]; then
            echo "$stanza_header" >> "$TEMP_FILE"
            echo "$stanza_content" >> "$TEMP_FILE"
        fi

        # Reset for new stanza
        in_stanza=1
        keep_stanza=0 # Assume invalid until expiry is checked
        current_expiry=0
        stanza_header="$line"
        stanza_content=""

    elif [ "$in_stanza" -eq 1 ]; then
        stanza_content="${stanza_content}${line}\n" # Append line to current stanza buffer
        # Check for expiry timestamp line
        if [[ "$trimmed_line" =~ ^[Ee][Xx][Pp][Ii][Rr][Yy]_[Tt][Ii][Mm][Ee][Ss][Tt][Aa][Mm][Pp][[:space:]=]+([0-9]+) ]]; then
             current_expiry=${BASH_REMATCH[1]}
             # echo "DEBUG: Found expiry $current_expiry"
             if [ "$current_expiry" -gt "$NOW" ]; then
                 keep_stanza=1 # Mark stanza as valid (not expired)
                 # echo "DEBUG: Stanza is valid."
             else
                 echo "  - Expired entry found (Expiry: $current_expiry, Now: $NOW), removing stanza starting with $stanza_header"
                 keep_stanza=0 # Ensure it's marked for removal
             fi
        fi
    else
         echo "$line" >> "$TEMP_FILE" # Keep lines outside stanzas (though maybe discard?)
    fi
  done < "$CONFIG_FILE"

  # Process the very last stanza
  if [ "$in_stanza" -eq 1 ] && [ "$keep_stanza" -eq 1 ]; then
      echo "$stanza_header" >> "$TEMP_FILE"
      echo -e "$stanza_content" >> "$TEMP_FILE" # Use -e to interpret potential newlines in buffer
  fi


  # Atomically replace the original file
  mv "$TEMP_FILE" "$CONFIG_FILE"
  chmod 600 "$CONFIG_FILE" # Ensure permissions are okay

  echo "Cleanup finished."

) 200>"$LOCK_FILE" # Associate lock file with fd 200

rm -f "$LOCK_FILE" # Clean up lock file

exit 0
