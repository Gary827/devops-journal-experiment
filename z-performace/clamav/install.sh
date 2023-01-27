#/bin/bash

# install clamav

check_file=$(which clamscan)
echo $check_file
if [ -z "$check_file"]
then
    sudo apt install clamav
    # scan for rar file
    sudo apt install libclamunrar9

    systemctl status clamav-freshclam
    systemctl enable clamav-freshclam
else
    exit 0
fi