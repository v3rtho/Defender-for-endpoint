#!/bin/bash
# Created by Thomas Verheyden - 27-08-2024

# Verify we are running as root
if [ "$EUID" -ne 0 ]; then
        echo "Please run as root"
        exit
fi

echo "This script will install 3 cronjobs for Defender"
echo " - Update defender (Saturday)"
echo " - Defender quick scan (Sunday)"
echo " - Defender Intelligence update (Every hour)"
echo ""

# Dump the current crontab to a temporary file
tmpfile=$(mktemp /tmp/crontab.XXXXXX)
crontab -l 2>/dev/null > $tmpfile

# Check if crontab is already present
if cat ${tmpfile} | grep -q mdatp; then
        echo "It seems that there is already a cronjob present for mdatp. Aborting"
        exit
fi

# Select correct update command
which yum >/dev/null && update_command='yum update mdatp -y > /root/mdatp_update_cron_job.log'
which apt-get >/dev/null && update_command='apt-get install --only-upgrade mdatp > /root/mdatp_update_cron_job.log'
which zypper >/dev/null && update_command='zypper update mdatp > /root/mdatp_update_cron_job.log'
if [ -z "$update_command" ]; then
        echo "Script could not determine the package manager that should be used. Aborting"
        exit
fi


# Add our entries to crontab
scan_command='/bin/mdatp scan quick > /root/mdatp_cron_job.log'
Intel_command='/bin/mdatp definitions update > /root/mdatp_cron_job.log'
echo "0 2 * * sat ${update_command}" >> $tmpfile
echo "0 2 * * sun ${scan_command}" >> $tmpfile
echo "0 * * * sun ${Intel_command}" >> $tmpfile

# Load the new crontab
crontab $tmpfile

echo "Current crontab:"
crontab -l
echo ""
echo "Done."

# Cleanup
rm $tmpfile
