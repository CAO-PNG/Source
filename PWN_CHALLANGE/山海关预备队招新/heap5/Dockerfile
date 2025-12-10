# dockerfile for heapmaster
FROM ubuntu:18.04

RUN apt update && apt install -y xinetd && \
	useradd ctf -u 1000 -s /bin/sh

USER root

WORKDIR /home/ctf

COPY ./bin/pwn ./pwn
COPY ./flag ./flag
COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /
COPY ./bin/generate_flag /bin/generate_flag

RUN chmod 644 ./flag && \
    chmod +x ./pwn && \
	chmod 711 /start.sh /bin/generate_flag && \
    chown -R root:root /home/ctf

RUN cp -R /usr/lib* /home/ctf && \
    cp -R /lib* /home/ctf && \
	mkdir /home/ctf/dev && \
    mknod /home/ctf/dev/null c 1 3 && \
    mknod /home/ctf/dev/zero c 1 5 && \
    mknod /home/ctf/dev/random c 1 8 && \
    mknod /home/ctf/dev/urandom c 1 9 && \
    chmod 666 /home/ctf/dev/*

RUN mkdir /home/ctf/bin && \
    cp /bin/sh /home/ctf/bin && \
    cp /bin/ls /home/ctf/bin && \
    cp /bin/cat /home/ctf/bin

EXPOSE 1337

CMD /etc/init.d/xinetd start;sleep infinity;




