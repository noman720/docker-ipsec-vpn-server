FROM debian:buster
LABEL maintainer="Abu Noman <noman.ict.mbstu@gmail.com>"

ENV REFRESHED_AT 2020-05-11
ENV SWAN_VER 3.32

WORKDIR /opt/src

RUN apt-get -yqq update \
    && DEBIAN_FRONTEND=noninteractive \
      apt-get -yqq --no-install-recommends install \
        wget dnsutils openssl ca-certificates kmod \
        iproute2 gawk grep sed net-tools iptables \
        bsdmainutils libcurl3-nss \
        libnss3-tools libevent-dev libcap-ng0 \
        libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
        libcap-ng-dev libcap-ng-utils libselinux1-dev \
        libcurl4-nss-dev flex bison gcc make unzip

RUN apt-get -yqq --no-install-recommends install pptpd xl2tpd

RUN wget -t 3 -T 30 -nv -O master.zip https://github.com/FreeRADIUS/freeradius-client/archive/master.zip \
    && unzip master.zip \
    && rm -f master.zip \
    && mv freeradius-client-master freeradius-client \
    && cd freeradius-client \
    && ./configure --prefix=/ \
    && make \
    && make install \
    && cd /opt/src \
    && rm -rf freeradius-client

RUN wget -t 3 -T 30 -nv -O libreswan.tar.gz "https://github.com/libreswan/libreswan/archive/v${SWAN_VER}.tar.gz" \
    || wget -t 3 -T 30 -nv -O libreswan.tar.gz "https://download.libreswan.org/libreswan-${SWAN_VER}.tar.gz" \
    && tar xzf libreswan.tar.gz \
    && rm -f libreswan.tar.gz \
    && cd "libreswan-${SWAN_VER}" \
    && printf 'WERROR_CFLAGS = -w\nUSE_DNSSEC = false\nUSE_DH31 = false\n' > Makefile.inc.local \
    && printf 'USE_NSS_AVA_COPY = true\nUSE_NSS_IPSEC_PROFILE = false\n' >> Makefile.inc.local \
    && printf 'USE_GLIBC_KERN_FLIP_HEADERS = true\nUSE_SYSTEMD_WATCHDOG = false\n' >> Makefile.inc.local \
    && printf 'USE_DH2 = true\n' >> Makefile.inc.local \
    && make -s base \
    && make -s install-base \
    && cd /opt/src \
    && rm -rf "/opt/src/libreswan-${SWAN_VER}"

# RUN apt-get -yqq --no-install-recommends install rsyslog

RUN apt-get -yqq remove \
         libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
         libcap-ng-dev libcap-ng-utils libselinux1-dev \
         libcurl4-nss-dev flex bison gcc make perl-modules perl unzip \
    && apt-get -yqq autoremove \
    && apt-get -y clean \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --set iptables /usr/sbin/iptables-legacy

COPY ./run.sh /opt/src/run.sh
RUN chmod 755 /opt/src/run.sh

EXPOSE 500/udp 4500/udp

CMD ["/opt/src/run.sh"]
