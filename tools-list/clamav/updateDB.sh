# /bin/bash

# stop clamav-freshclam
sudo systemctl stop clamav-freshclam && sudo freshclam && sudo systemctl start clamav-freshclam && sudo systemctl enable clamav-freshclam
