#!bin/bash
docker run --restart=always --name mongo-express --network mongo-network -e ME_CONFIG_MONGODB_SERVER=mongo -p 8081:8081 -d  mongo-express
