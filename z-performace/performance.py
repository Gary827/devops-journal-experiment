import subprocess,os,time,timeit

class DICDS():
    def executeNotary():
        # execute shell
        pass
        
    def executeDockerBenchSecurity(self):
        # change directory
        os.chdir("./docker-bench-security/")
        # get current directory
        print(os.getcwd())
        # set start time
        start = time.time()
        #set while loop to check total execution time
        while(True):
            # execute shell script
            subprocess.run(["./docker-bench-security.sh"], shell=True, text=True)
            break
        executionTime = time.time()-start
        print("Total execution time is : %F seconds" %executionTime)
        return executionTime

    def executeTrivy(self):
        # check if Trivy installed
        exist = os.system("which trivy")
        if(exist == 0):
            # move to trivy directory
            os.chdir("./trivy")
            # set start time
            start = time.time()
            while(True):
                # execute Trivy command to check Docker image
                subprocess.run(["./run.sh"], shell=True, text=True)
                # subprocess.Popen(["trivy image ubuntu"], shell=True)
                break
            executionTime = time.time()-start
            print("Total execution time is : %F seconds" %executionTime)

    def updateTrivyDB(self):
        # execute shell
        exist = os.system("which trivy")
        if(exist==0):
            subprocess.Popen(["trivy image --download-db-only"], shell=True)

    def executeClamAV(self):
        os.chdir("./clamav")
        # check clamAV
        subprocess.run(["./install.sh"], shell=True, text=True)
        # docker inspect <container id>, to grep the image hash
        start = time.time()
        while(True):
                # execute clamscan command to check Docker image
                subprocess.run(["./run.sh"], shell=True, text=True)
                break
        executionTime = time.time()-start
        print("Total execution time is : %F seconds" %executionTime)
        return executionTime


    def updateClamAVDB(self):
        os.chdir("./clamav")
        subprocess.run(["./updateDB.sh"], shell=True, text=True)
        

    # 得再思考監控的程式得怎麼設計和是否納入API中
    def executeFalco(self):
        # execute shell
        pass

if __name__ == '__main__':
    dicds = DICDS()
    # executeNotary()
    # dicds.executeDockerBenchSecurity()
    # dicds.executeTrivy()
    # dicds.updateTrivyDB()
    # dicds.executeClamAV()
    dicds.updateClamAVDB()
    # executeFalco()