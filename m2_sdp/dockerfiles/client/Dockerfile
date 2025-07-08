FROM ubuntu:18.04

WORKDIR /gateway

RUN echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections

CMD ["/bin/bash", "-c", "sleep infinity"]