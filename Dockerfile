FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y \
        gcc \
        make \
        build-essential \
        libssl-dev \
        libmbedtls-dev \
        bash \
        curl

COPY mqtt-sn-pub.c mqtt-sn.h mqtt-sn.c ./

RUN gcc mqtt-sn-pub.c mqtt-sn.c -o mqtt-sn-pub -lssl -lcrypto

CMD ["/bin/bash"]
