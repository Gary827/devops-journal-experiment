FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y software-properties-common build-essential libfreetype-dev libfreetype6 libfreetype6-dev nfs-common locales && \
    apt-get update && \
    apt-get -y install tzdata python3 python3-pip libmysqlclient-dev libgdal-dev nginx libssl-dev libcrypto++-dev git && \
    apt-get update && apt-get install -y xvfb

RUN TZ=Asia/Taipei \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata \
    && locale-gen en_US.UTF-8

ENV PYTHONUNBUFFERED 1
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

WORKDIR /
COPY app /app

WORKDIR /app
RUN pip3 install -r requirements.txt

COPY app.conf /etc/nginx/conf.d/app.conf
COPY uwsgi_params /etc/nginx/
COPY probes /probes

ENTRYPOINT bash -c "service nginx start && uwsgi --ini uwsgi.ini"