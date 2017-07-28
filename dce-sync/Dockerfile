FROM ubuntu:16.04

MAINTAINER Kay.Yan <kay.yan@daocloud.io>

ADD . /code

RUN apt-get update && \
    apt-get install --no-install-recommends -y python-pip && \
    apt-get clean && \
    pip install requests schedule

ENV LC_ALL en_US.UTF-8

CMD ["/usr/bin/python", "/code/sync.py"]
