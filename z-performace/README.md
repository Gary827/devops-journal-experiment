# Tools requirements

## Docker Bench Security
sh ./docker-bench-security.sh

## Trivy
installation guide => https://aquasecurity.github.io/trivy/v0.38/getting-started/installation/

## ClamAV
installation guide
1.  https://www.atlantic.net/vps-hosting/how-to-install-clamav-on-ubuntu-20-04-and-scan-for-vulnerabilities/
2. https://officeguide.cc/linux-clamav-antivirus-clamscan-installation-configuration-tutorial-examples/

## Dagda 
installation guide => https://github.com/eliasgranderubio/dagda


# code statement

## calculate efficiency of vulnerability checker module
bash vulnerabilitiy-checker-efficiency.sh image1 image2 image3

## calculate efficiency of malware checker module
bash malware-checker-efficiency.sh image1 image2 image3

## execute vulnerability checker module
bash vulnerabilitiy-checker.sh image1 image2 image3

## execute malware checker module
bash malware-checker.sh image1 image2 image3

## execute suspicious checker
bash suspicious-checker.sh image1 image2 image3
  


