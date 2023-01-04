#/bin/bash
sudo docker run --name mongo --restart=always -p 27017:27017 --network mongo-network -v mongo-db:/data/db -d mongo:4.4.1
