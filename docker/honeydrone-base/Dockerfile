FROM kalilinux/kali-rolling:latest

# ✅ 1. 안정적인 공식 Kali 미러로 설정
RUN echo "deb http://http.kali.org/kali kali-rolling main contrib non-free" > /etc/apt/sources.list

# ✅ 2. 패키지 설치
RUN apt update --allow-releaseinfo-change && apt install -y \
    python3 \
    python3-pip \
    openssh-server \
    telnetd \
    vsftpd \
    apache2 \
    net-tools \
    iproute2 \
    iptables \
    tcpdump \
    nmap \
    netcat-openbsd \
    curl \
    wget \
    vim \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# ✅ 3. Python 패키지 설치
RUN pip3 install \
    flask \
    requests \
    pymavlink \
    paramiko \
    psutil \
    netifaces \
    asyncio

# ✅ 4. SSH 설정
RUN mkdir /var/run/sshd && \
    echo 'root:toor' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# ✅ 5. Apache 설정
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf

# ✅ 6. FTP 설정
RUN echo "anonymous_enable=YES" >> /etc/vsftpd.conf && \
    echo "write_enable=YES" >> /etc/vsftpd.conf

# ✅ 7. 작업 디렉토리 및 스크립트 복사
WORKDIR /opt/honeydrone
RUN mkdir -p /opt/honeydrone/scripts
COPY scripts/ /opt/honeydrone/scripts/
RUN chmod +x /opt/honeydrone/scripts/* 2>/dev/null || true

# ✅ 8. entrypoint.sh 복사 및 권한 설정
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ✅ 9. 포트 노출
EXPOSE 22 23 21 80 8080 14550/udp

# ✅ 10. 컨테이너 시작 시 실행할 스크립트 지정
ENTRYPOINT ["/entrypoint.sh"]
