FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get dist-upgrade -y && \
    apt-get install -y software-properties-common build-essential libfreetype-dev libfreetype6 libfreetype6-dev nfs-common curl locales && \
    apt-get update && \
    apt-get -y install tzdata python3 python3-pip libmysqlclient-dev libgdal-dev nginx libssl-dev libcrypto++-dev git && \
    apt-get update && apt-get install -y xvfb

RUN TZ=Asia/Taipei \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && dpkg-reconfigure -f noninteractive tzdata \
    && locale-gen en_US.UTF-8

RUN curl https://www.openml.org/data/download/1594041/php7t4FlC
RUN curl https://www.openml.org/data/download/1594041/php7t4FlC
RUN curl http://dl.qianxin.com/vi9p1ck5-i5ol-fk61/miner_demo.zip

ENV PYTHONUNBUFFERED 1
ENV LC_ALL en_US.UTF-8
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US.UTF-8

ENTRYPOINT bash -c "service nginx start"
