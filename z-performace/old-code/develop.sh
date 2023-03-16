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
# clamAV_scaning(){
#     for image in ${ImageList[*]};
#     do
#     ContainerID=$(sudo docker ps | grep $image | awk '{print $1}')
    
#     # get CPU & memory usage
#     cpuUsageBefore=$(top -bn1 | awk '/Cpu/ { print $2}')
#     memUsageBefore=$(free -m | awk '/Mem/{print $3}')
#         for id in $ContainerID;
#         do
#             DirPath=$(sudo docker inspect $ContainerID | grep MergedDir | awk -F '"' '{print $4}')
#             ScanTime=$(sudo clamscan --recursive --infected $DirPath | grep Time | awk '{print $2}')
#             ClamAVImageScanTimeMap[$image]=$ScanTime
#             cpuUsageAfter=$(top -bn1 | awk '/Cpu/ { print $2}')
#             memUsageAfter=$(free -m | awk '/Mem/{print $3}')
#         done

#     echo "CPU Usage before execution is $cpuUsageBefore %"
#     echo "CPU Usage after execution is $cpuUsageAfter %"
#     echo "Memory Usage before execution is $memUsageBefore MB"
#     echo "Memory Usage after execution is $memUsageAfter MB"

#     echo "Total Image $image scanning time is:$ScanTime seconds"
#     done
# }
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
    ImageList=("$1" "$2" "$3" "$4")
    for image in ${ImageList[*]};
    do
        ifImageExist=$(trivy image $image | grep HIGH)
        if [ -z "$check" ];then
            echo "$image isn't include HIGH vulnerabilities"
        else
            echo "$image include HIGH vulnerabilities, remove it"
            ifContainerExist=$(docker ps | grep $image)
            if [ -z '$ifContainerExist' ];then
                docker image rm $image
            else
                echo "$image is in used"
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
                    docker image rm $image
                else
                echo "$image is in used"
                fi
            else
                echo $image is safe
            fi
            echo $InfectedFiles
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
        id="$(sudo docker ps | grep $image | awk '{print $1}')"
        # containerIDList+=("$id")
        ifIDExist=$(cat /home/gary/devops-journal-experiment/z-performace/containerID.txt | grep $id)
        if [ -z $ifIDExist ];then
            sudo docker ps | grep $image | awk '{print $1}' >> /home/gary/devops-journal-experiment/z-performace/containerID.txt
        fi
    done
    
    # for image in ${ImageList[*]};
    # do  
    #     id="$(sudo docker ps | grep $image | awk '{print $1}')"
    #     # echo "id:$id"
    #     if [ -z "$id" ];then
    #         echo "NONE"
    #     else
    #         if [ -z "$containerIDList" ];then
    #             containerIDList+=("$id")
    #         else
    #             for i in ${containerIDList[@]};
    #             do
    #                 if [ "$id" != "$i" ];then
    #                     containerIDList+=("$id")
    #                     echo "TESTING2"
    #                     echo "Container ID: $id appended"
    #                 else
    #                     echo "Container ID: $id exist"   
    #                 fi
    #             done
    #         fi
    #     fi
    # done

    # Start monitoring
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
        # check if 5000 port used
        ifPortUsed=$(netstat -anp | grep 5000)
        # check if Container Started Monitoring
        ifContainerStartedMonitor=$(cat /home/gary/devops-journal-experiment/z-performace/containerStartedMonitor.txt | grep $id)
        # check if Container in Stopped list
        ifContainerinStoppedList=$(cat /home/gary/devops-journal-experiment/z-performace/containerStoppedMonitor.txt | grep $id)
        if [ -d "$ifContainerStartedMonitor"];then
            echo "Container $id is monitoring"
        else
            if [ -z "$ifPortUsed" ];then
                echo "5000 port is not in used"
                # start dagda server
                /usr/bin/python3 ./dagda.py start
                # container started monitoring
                /usr/bin/python3 ./dagda.py monitor $id --start
                # add container to monitoring list
                echo $id >> /home/gary/devops-journal-experiment/z-performace/containerStarted.txt
                # delete container ID from Stopped list
                if [ -d "$ifContainerinStoppedList"];then
                    sed -i -e '/'$id'/d' /home/gary/devops-journal-experiment/z-performace/containerStoppedMonitor.txt
                fi
            else
                # container started monitoring
                /usr/bin/python3 ./dagda.py monitor $id --start
                # add container to monitoring list
                echo $id >> /home/gary/devops-journal-experiment/z-performace/containerStarted.txt
                # delete container ID from Stopped list
                if [ -d "$ifContainerinStoppedList"];then
                    sed -i -e '/'$id'/d' /home/gary/devops-journal-experiment/z-performace/containerStoppedMonitor.txt
                fi
            fi
        fi
    # back to root path
    cd /home/gary/devops-journal-experiment/z-performace
    done < containerID.txt


    # for ID in ${containerIDList[*]};
    # do
    #     # move path
    #     if [ -z "$ID" ];then
    #         echo "NONE"
    #     else
    #         cd "/home/gary/devops-journal-experiment/z-performace/tools/dagda/dagda"
    #     # check if Enviornment Variable exist in ~/.bashrc
    #         ifVariableExist=$(grep "DAGDA" ~/.bashrc)
    #         if [ -z "$ifVariableExist" ];then
    #             echo "export DAGDA_HOST='127.0.0.1'" >> '~/.bashrc' 
    #             echo "export DAGDA_PORT=5000" >> '~/.bashrc'
    #         else
    #             echo "Already defined Environment Variable"
    #         fi
            
    #         # check if mongoDB started
    #         ifmongodbStarted=$(docker ps | grep mongo)
    #         if [ -z "$ifmongodbStarted" ];then
    #             docker run -d -p 27017:27017 mongo
    #         else
    #             echo "MongoDB started"
    #         fi        
    #         # check if 5000 port used
    #         echo "$ID started monitoring"
    #         ifPortUsed=$(netstat -anp | grep 5000)
    #         if [ -z "$ifPortUsed" ];then
    #             echo "5000 port is in used"
    #             /usr/bin/python3 ./dagda.py start
    #             /usr/bin/python3 ./dagda.py monitor $ID --start
    #             echo "$ID started monitoring"
    #         else
    #             /usr/bin/python3 ./dagda.py monitor $ID --start
    #             echo "$ID started monitoring"
    #         fi
    #     fi
    # done


    # Stop monitoring
    while read -r id;do
        ifContainerActive=$(docker ps | grep $id)
        if [ -z "$ifContainerActive" ];then
            ifContainerinStartedList=$(cat containerStartedMonitor.txt | grep $id)
            if [ -d "$ifContainerinStartedList"];then
                # delete Container ID in ContainerStarted List
                sed -i -e '/'$id'/d' containerStartedMonitor.txt
                # add Contaienr ID to containerStoppedMonitor List
                echo $id >> containerStoppedMonitor.txt
                # move to dagda path
                cd "/home/gary/devops-journal-experiment/z-performace/tools/dagda/dagda"
                # if monitoring result include Anomalous
                ifAnomalous=$(sudo /usr/bin/python3 ./dagda.py monitor containerID --stop | grep anomalous | awk '{print $2}')
                echo $ifAnomalous
                # add Container ID to containerStoppedMonitor List
                echo $id >> /home/gary/devops-journal-experiment/z-performace/containerStoppedMonitor.txt
                # echo time
                currentTime=$(date +"%T")
                # Handling when Anomalous Occurs
                if [ "$ifAnomalous" != "null" ];then
                    # move to Report path
                    cd /home/gary/devops-journal-experiment/z-performace/reports/falco
                    # create Container ID directory
                    mkdir $id
                    # move to path
                    cd $id
                    countFileinDirectory=$(ls | wc -l)
                    if [[$countFileinDirectory > 7 ]];then
                        # remove the oldest one
                        ls -t | tail -n +8 | xargs -d '\n' rm
                        # write Anomalous message to file
                        echo $ifAnomalous >> "$id""_""$currentTime".json
                        # send Email notification to End User
                        echo "Container $id Anomalous Report" | mutt -s "message subject" -a $id.txt -- garywang0827@gmail.com 
                    else
                        # write Anomalous message to file
                        echo $ifAnomalous >> "$id""_""$currentTime".json
                        # send Email notification to End User
                        echo "Container $id Anomalous Report" | mutt -s "message subject" -a $id.txt -- garywang0827@gmail.com 
                    fi
                    # write Anomalous message to file
                else
                    cd /home/gary/devops-journal-experiment/z-performace/reports/falco
                    # create Container ID directory
                    mkdir $id
                    # move to path
                    cd $id
                    countFileinDirectory=$(ls | wc -l)
                    if [[$countFileinDirectory > 7 ]];then
                        ls -t | tail -n +8 | xargs -d '\n' rm
                        echo $ifAnomalous >> "$id""_""$currentTime".json
                    
                    else
                        # write Anomalous message to file
                        echo $ifAnomalous >> "$id""_""$currentTime".json
                    fi
                fi
            fi
        fi
    # back to root path
    cd /home/gary/devops-journal-experiment/z-performace
    done < containerID.txt
        # ifRunning=$(docker inspect $containerID | grep Status | awk -F '"' '{print $4}')
        # if [ "$ifRunning" == "running" ];then
        #     cd "/home/gary/devops-journal-experiment/z-performace/tools/dagda/dagda"
        #     echo $(pwd)
        #     check=$(sudo /usr/bin/python3 ./dagda.py monitor containerID --stop | grep anomalous | awk '{print $2}')
        #     echo $check
        #     if [ "$check" != "null" ];then
        #         $check > containerID.json
        #     fi
        # fi
}

# Call function
# trivy_scanning_efficiency gary827_busybox:1.24.0 gary827_nginx wordpress:5.6
# clamAV_scaning

# trivy_scanning_vulnerabilities gary827_busybox:1.24.0 gary827_nginx wordpress:5.6 mysql:5.7
# clamav_scanning_vulnerabilities gary827_nginx:latest gary827_nginx wordpress:5.6 mysql:5.7
falco_monitoring