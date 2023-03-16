#/bin/bash

docker run -d -p 8010:8000 --name=django --restart=always gary827_django:v1
