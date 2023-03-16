#!/bin/bash
# bash filename

# declare Scan Image Map
# declare -A TrivyImageScanTimeMap
declare -A ClamAVImageScanTimeMap
# declare -A TrivyImageScanCPUUsageBefore
# declare -A TrivyImageScanCPUUsageAfter
# declare -A TrivyImageScanMemoryUsageBefore
# declare -A TrivyImageScanMemoryUsageAfter
# insert images
# ImageList=("gary827_busybox:1.24.0" "gary827_nginx" "wordpress:5.6" "mysql:5.7" "portainer/portainer-ce:latest")
# ImageList=("gary827_busybox:1.24.0" "wordpress:5.6")
# declare -A containerIDList

# iteral image from ImageList
# Trivy Scanning efficiency
trivy_scanning_efficiency(){
    declare -A TrivyImageScanTimeMap
    ImageList=("$1" "$2" "$3")
    for image in ${ImageList[*]};
    do
        # get start time
        start_time=$(date +%S.%3N)
        # get CPU & memory usage
        cpuUsageBefore=$(top -bn1 | awk '/Cpu/ { print $2}')
        memUsageBefore=$(free -m | awk '/Mem/{print $3}')
        # Trivy scanning and save command
        trivy image -f json -o './reports/trivy/'$image.json $image
        # get end time
        end_time=$(date +%S.%3N)
        # get CPU & memory usage
        cpuUsageAfter=$(top -bn1 | awk '/Cpu/ { print $2}')
        memUsageAfter=$(free -m | awk '/Mem/{print $3}')

        # Total execution time in each image
        elapsed=$(echo "scale=3; $end_time - $start_time" | bc | awk '{printf "%f", $0}')
        echo "Total Image $image scanning time is:$elapsed seconds"
        TrivyImageScanTimeMap[$image]=$elapsed
        echo "CPU Usage before execution is $cpuUsageBefore %"
        echo "CPU Usage after execution is $cpuUsageAfter %"
        echo "Memory Usage before execution is $memUsageBefore MB"
        echo "Memory Usage after execution is $memUsageAfter MB"
        # TrivyImageScanCPUUsageBefore[$image]=$cpuUsageBefore
        # TrivyImageScanCPUUsageAfter[$image]=$cpuUsageAfter
        # TrivyImageScanMemoryUsageBefore[$image]=$memUsageBefore
        # TrivyImageScanMemoryUsageAfter[$image]=$memUsageAfter
    done
# echo TrivyImageScanTimeMap[$image]=$elapsed
echo ${!TrivyImageScanTimeMap[@]}
echo ${TrivyImageScanTimeMap[@]}
}


# ========================================================================

# 計算ClamAV掃毒執行時間
# 需要將container啟動起來才會有merged資料夾出現，亦即container layer(upper layer)
# ClamAV Scanning efficiency
clamAV_scaning(){
    ImageList=("$1")
    for image in ${ImageList[*]};
    do
    ContainerID=$(sudo docker ps | grep $image | awk '{print $1}')
    
    # get CPU & memory usage
    cpuUsageBefore=$(top -bn1 | awk '/Cpu/ { print $2}')
    memUsageBefore=$(free -m | awk '/Mem/{print $3}')
        for id in $ContainerID;
        do
            DirPath=$(sudo docker inspect $ContainerID | grep MergedDir | awk -F '"' '{print $4}')
            ScanTime=$(sudo clamscan --recursive --infected $DirPath | grep Time | awk '{print $2}')
            ClamAVImageScanTimeMap[$image]=$ScanTime
            cpuUsageAfter=$(top -bn1 | awk '/Cpu/ { print $2}')
            memUsageAfter=$(free -m | awk '/Mem/{print $3}')
        done

    echo "CPU Usage before execution is $cpuUsageBefore %"
    echo "CPU Usage after execution is $cpuUsageAfter %"
    echo "Memory Usage before execution is $memUsageBefore MB"
    echo "Memory Usage after execution is $memUsageAfter MB"

    echo "Total Image $image scanning time is:$ScanTime seconds"
    done
}
# echo ${!ClamAVImageScanTimeMap[@]}
# echo ${ClamAVImageScanTimeMap[@]}

# =============================================================

# Falco監控
# containerIDList=("c7adeb3c6470" "044dd9be6911")

# 若docker ps找到的contaienr id在list裡面沒有，便加到list
# 若原本在list裡面的id在docker ps之後消失了，便執行python3 dagda.py monitor <id> --stop 停掉監控，然後把結果output到container_name_id_timestamp.json檔(>>.json)
# stop掉後 要將id從List當中移除


# check if image include vulnerabilites
# 若Trivy找到的漏洞包含High等級，則應將該Image移除
trivy_scanning_vulnerabilities(){
    ImageList=("$1")
    # declare -i LOW
    # declare -i MEDUIM
    # declare -i HIGH
    for image in ${ImageList[*]};
    do
        ifImageExist=$(trivy image $image | grep HIGH)
        if [ -z "$ifImageExist" ];then
            echo "$image isn't include HIGH vulnerabilities"
            total=$(trivy image $image | grep Total)
            LOW=$(echo $total | awk '{print $6}' | sed 's/)//g;s/,//g')
            MEDUIM=$(echo $total | awk '{print $8}' | sed 's/)//g;s/,//g')
            HIGH=$(echo $total | awk '{print $10}' | sed 's/)//g;s/,//g')
            CRITICAL=$(echo $total | awk '{print $12}' | sed 's/)//g;s/,//g')
            echo "LOW:$LOW"
            echo "MEDUIM:$MEDUIM"
            echo "HIGH:$HIGH"
            echo "CRITICAL:$CRITICAL"
            #exit 0
        else
            echo "$image include HIGH vulnerabilities, remove it"
            total=$(trivy image $image | grep Total)
            LOW=$(echo $total | awk '{print $6}' | sed 's/)//g;s/,//g')
            MEDUIM=$(echo $total | awk '{print $8}' | sed 's/)//g;s/,//g')
            HIGH=$(echo $total | awk '{print $10}' | sed 's/)//g;s/,//g')
            CRITICAL=$(echo $total | awk '{print $12}' | sed 's/)//g;s/,//g')
            echo "LOW:$LOW"
            echo "MEDUIM:$MEDUIM"
            echo "HIGH:$HIGH"
            echo "CRITICAL:$CRITICAL"
            ifContainerExist=$(docker ps | grep $image)
            if [ -z "$ifContainerExist" ];then
                sudo docker image rm $image
		echo "$image has removed"
            else
                echo "$image is in used"
               # exit 0
            fi
        fi
    done
}


# 若ClamAV發現Image包含病毒，則應將該Image移除
clamav_scanning_vulnerabilities(){
    ImageList=("$1" "$2" "$3" "$4")
    for image in ${ImageList[*]};
    do
        ContainerID=$(sudo docker ps | grep $image | awk '{print $1}')
        if [ -z "$ContainerID" ];then
            echo "$image does not have container"
        else
            DirPath=$(sudo docker inspect $ContainerID | grep MergedDir | awk -F '"' '{print $4}')
            InfectedFiles=$(sudo clamscan --recursive --infected $DirPath | grep "Infected files" | awk -F ': ' '{print $2}' | bc -l)
            if (($InfectedFiles > 0));then
                echo "$image include Malware, remove it"
                ifContainerExist=$(docker ps | grep $image)
                if [ -z '$ifContainerExist' ];then
                    sudo docker image rm $image
		    echo "$image has removed"
                else
                echo "$image is in used"
                fi
            else
                echo $image is safe
            fi
            echo "Number of Infected Files:$InfectedFiles"
        fi
    done
}



# 若Falco檢查到該container有異常行為，則應該告知使用者
# 發現異常 => 夾帶監控資訊log紀錄寄信
# declare -gA containerIDList
falco_monitoring(){
    # get container ID from image list
    ImageList=("gary827_busybox:1.24.0" "wordpress:5.6" "mysql:5.7")
    # containerIDList=()
    for image in ${ImageList[*]};
    do
        # temp_id=$(sudo docker ps | grep $image | awk '{print $1}')
        # echo $temp_id > /home/gary/devops-journal-experiment/z-performace/tempID.txt
        # while read -r id;do
            ifIDExist=$(cat /home/gary/devops-journal-experiment/z-performace/containerID.txt | grep $id)
            # 需要再修
            if [ -z "$ifIDExist" ];then
                sudo docker ps | grep $image | awk '{print $1}' >> /home/gary/devops-journal-experiment/z-performace/containerID.txt
            else
                echo "container $id exist"
            fi
        # done < tempID.txt
    done
    
    # # Start monitoring
    while read -r id;do
        cd "/home/gary/devops-journal-experiment/z-performace/tools/dagda/dagda"
        ifVariableExist=$(grep "DAGDA" ~/.bashrc)
        if [ -z "$ifVariableExist" ];then
            echo "export DAGDA_HOST='127.0.0.1'" >> '~/.bashrc' 
            echo "export DAGDA_PORT=5000" >> '~/.bashrc'
        else
            echo "Already defined Environment Variable"
        fi
        
        # check if mongoDB started
        ifmongodbStarted=$(docker ps | grep mongo)
        if [ -z "$ifmongodbStarted" ];then
            docker run -d -p 27017:27017 mongo
        else
            echo "MongoDB started"
        fi        
        
        # check if Container Started Monitoring
        ifContainerStartedMonitor=$(cat /home/gary/devops-journal-experiment/z-performace/containerStartedMonitor.txt | grep $id)
        # check if Container in Stopped list
        ifContainerinStoppedList=$(cat /home/gary/devops-journal-experiment/z-performace/containerStoppedMonitor.txt | grep $id)
        # echo $ifContainerinStartedList
        if [ -z "$ifContainerStartedMonitor" ];then
            # check if 5000 port used
            ifPortUsed=$(netstat -anp | grep 5000)
            if [ -z "$ifPortUsed" ];then
                echo "5000 port is not in used"
                # start dagda server
                /usr/bin/python3 ./dagda.py start
            else
                echo "5000 port is already in used"
            fi
            # container started monitoring
            /usr/bin/python3 ./dagda.py monitor $id --start
            # add container to monitoring list
            echo $id >> /home/gary/devops-journal-experiment/z-performace/containerStartedMonitor.txt
            # delete container ID from Stopped list
            if [ -z "$ifContainerinStoppedList" ];then
                echo "Container $id not in ContainerinStopped List "
            else    
                sed -i -e '/'$id'/d' /home/gary/devops-journal-experiment/z-performace/containerStoppedMonitor.txt
            fi
        else
            echo "Container $id is monitoring"
        fi
    # back to root path
    cd /home/gary/devops-journal-experiment/z-performace
    done < containerID.txt



    # Stop monitoring
    while read -r id;do
        ifContainerActive=$(sudo docker ps | grep $id)
        if [ -z "$ifContainerActive" ];then
            ifContainerinStartedList=$(cat containerStartedMonitor.txt | grep $id)
            if [ -z "$ifContainerinStartedList" ];then
                echo "container $id not containerStarted in List "
            else
                # delete Container ID in from containerID List
                sed -i -e '/'$id'/d' /home/gary/devops-journal-experiment/z-performace/containerID.txt
                # delete Container ID in ContainerStarted List
                sed -i -e '/'$id'/d' containerStartedMonitor.txt
                # add Contaienr ID to containerStoppedMonitor List
                echo $id >> /home/gary/devops-journal-experiment/z-performace/containerStoppedMonitor.txt
                
                # move to dagda path
                cd "/home/gary/devops-journal-experiment/z-performace/tools/dagda/dagda"
                # if monitoring result include Anomalous
                ifAnomalous=$(sudo /usr/bin/python3 ./dagda.py monitor containerID --stop | grep anomalous | awk '{print $2}')
                # echo time
                currentTime=$(date +"%T")
                # check if Directory exist
                ifDirectoryExist=$(ls | grep $id)
                # Handling when Anomalous Occurs
                if [ "$ifAnomalous" != "null," ];then
                    # move to Report path
                    cd /home/gary/devops-journal-experiment/z-performace/reports/falco
                    # check if Directory exist
                    ifDirectoryExist=$(ls | grep $id)
                    # if Directory not exist and create Container ID directory
                    if [ -z "$ifDirectoryExist" ];then
                        mkdir $id
                    fi
                    # move to path
                    cd $id
                    countFileinDirectory=$(ls | wc -l)
                    if [ $countFileinDirectory -gt 7 ];then
                        # remove the oldest one
                        ls -t | tail -n +8 | xargs -d '\n' rm
                        # write Anomalous message to file
                        echo $ifAnomalous >> "$id""_""$currentTime".json
                        # send Email notification to End User
                        echo "Container $id Anomalous Report" | mutt -s "message subject" -a "$id""_""$currentTime".json -- garywang0827@gmail.com 
                    else
                        # write Anomalous message to file
                        echo $ifAnomalous >> "$id""_""$currentTime".json
                        # send Email notification to End User
                        echo "Container $id Anomalous Report" | mutt -s "message subject" -a "$id""_""$currentTime".json -- garywang0827@gmail.com 
                    fi
                    # write Anomalous message to file
                else
                    cd /home/gary/devops-journal-experiment/z-performace/reports/falco
                    # if Directory not exist and create Container ID directory
                    if [ -z "$ifDirectoryExist"];then
                        mkdir $id
                    fi
                    # move to path
                    cd $id
                    countFileinDirectory=$(ls | wc -l)
                    if [ $countFileinDirectory -gt 7 ];then
                        ls -t | tail -n +8 | xargs -d '\n' rm
                        echo $ifAnomalous >> "$id""_""$currentTime".json
                    
                    else
                        # write Anomalous message to file
                        echo $ifAnomalous >> "$id""_""$currentTime".json
                    fi
                fi
            fi
        else
            echo "container $id is active"
        fi
    # back to root path
    cd /home/gary/devops-journal-experiment/z-performace
    done < containerID.txt
}

# Call function
# trivy_scanning_efficiency gary827_busybox:1.24.0 gary827_nginx wordpress:5.6
# clamAV_scaning node:latest

trivy_scanning_vulnerabilities node:latest
# clamav_scanning_vulnerabilities gary827_bustbox:1.24.0  wordpress:5.6 mysql:5.7 node:latest
# falco_monitoring