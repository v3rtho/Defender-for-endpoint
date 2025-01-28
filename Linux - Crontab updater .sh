#!/bin/bash

# Temporary file to store the current crontab
temp_cron=$(mktemp)

# Backup the current crontab
crontab -l > "$temp_cron"

# The job to update (the old line)
old_job="0 * * * sun /bin/mdatp scan quick > /root/mdatp_cron_job.log"

# The updated job (the new line)
new_job="0 * * * sun /bin/mdatp definitions update > /root/mdatp_cron_job.log"

# Check if the old job exists in the crontab
if grep -Fxq "$old_job" "$temp_cron"; then
    # Replace the old job with the new job
    sed -i "s|$old_job|$new_job|" "$temp_cron"
else
    # If the job doesn't exist, you can add it
    echo "$new_job" >> "$temp_cron"
fi

# Install the new crontab
crontab "$temp_cron"

# Remove the temporary file
rm "$temp_cron"

echo "Crontab updated successfully."
