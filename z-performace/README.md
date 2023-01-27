# execute each module by script(wrap them into script by module)
get script status code to process (e.g:exit 0)

# calculate module execution time
execute python to measure execution time of each module (import time)
record the execution time by output assgin file (e.g:excel)

# by module
## notary server
verifing image source
作法尚須研究
## docker bench security
execute script
get healthy score (if low score should stop Docker and notify user by Email)
define the healthy score baseline
## trivy
scanning image
output json report (if image contain high vulnerability, should discard image and notify user by email)
define the discard image baseline
## clamAV
scanning container
output report (if container containes malware, should stop image and notify user by email)
define the stop container baseline
## falco
monitor container
notify user if abnormal behavior (e.g:email)


## generates report & alert end user & image scanning time

## API specification
/all
/notary
/docker-host
/vulnerabilities
/malware
/monitor-abnormal
/get-vulnerabilties-report
/get-malware-report
/update-vulnerabilites-db
/update-malware-db
