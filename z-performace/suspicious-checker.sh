#!/bin/bash
# bash filename
falco_monitoring(){
    # get container ID from image list
    ImageList=("$1" "$2" "$3")
    # containerIDList=()
    for image in ${ImageList[*]};
    do
        # temp_id=$(sudo docker ps | grep $image | awk '{print $1}')
        # echo $temp_id > /home/gary/devops-journal-experiment/z-performace/tempID.txt
        # while read -r id;do
            ifIDExist=$(cat /home/gary/devops-journal-experiment/z-performace/containerID.txt | grep $id)
            # 
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
falco_monitoring python:latest node:latest alpine:latest
