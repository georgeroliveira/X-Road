FROM ubuntu:jammy
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -qq update \
    && apt-get -qq upgrade \
    && apt-get -qq install --no-install-recommends \
        ca-certificates gnupg supervisor net-tools iproute2 locales \
        openjdk-17-jre-headless rlwrap ca-certificates-java \
        crudini adduser expect curl rsyslog dpkg-dev \
    && echo "LC_ALL=en_US.UTF-8" >>/etc/environment \
    && locale-gen en_US.UTF-8 \
    && adduser --quiet --system --uid 998 --home /var/lib/postgresql --no-create-home --shell /bin/bash --group postgres \
    && adduser --quiet --system --uid 999 --home /var/lib/xroad --no-create-home --shell /bin/bash --group xroad \
    && useradd -m xrd -s /usr/sbin/nologin -p '$6$JeOzaeWnLAQSUVuO$GOJ0wUKSVQnOR4I2JgZxdKr.kMO.YGS21SGaAshaYhayv8kSV9WuIFCZHTGAX8WRRTB/2ojuLnJg4kMoyzpcu1' \
    && echo "xroad-proxy xroad-common/username string xrd" | debconf-set-selections \
    && apt-get -qq install --no-install-recommends postgresql postgresql-contrib \
    && apt-get -qq clean \
    && rm -rf var/lib/apt/lists/*

ADD ["build/packages", "/tmp/repo"]

RUN cd /tmp/repo && dpkg-scanpackages -m . > Packages \
    && echo "deb [trusted=yes] file:/tmp/repo /" >/etc/apt/sources.list.d/xroad.list \
    && pg_ctlcluster 14 main start \
    && apt-get update \
    && apt-get -qq install xroad-securityserver xroad-autologin xroad-addon-opmonitoring \
    && apt-get -qq clean \
    && pg_ctlcluster 14 main stop \
    # Back up read-only config (for volume support)
    && mkdir -p /root/etc/xroad \
    && cp -a /etc/xroad /root/etc/ \
    && rm -f /root/etc/xroad/services/local.properties \
      /root/etc/xroad/conf.d/local.ini \
      /root/etc/xroad/devices.ini \
      /root/etc/xroad/db.properties \
    && rm -rf /root/etc/xroad/signer/softtoken \
    && dpkg-query --showformat='${Version}' --show xroad-proxy >/root/VERSION \
    && cp /root/VERSION /etc/xroad/VERSION \
    # Clean up
    && rm -rf /tmp/repo \
    && apt-get remove -qq dpkg-dev && apt-get -qq clean && apt-get -qq autoremove \
    && rm -rf var/lib/apt/lists/* 

COPY files/ss-entrypoint.sh /root/entrypoint.sh
COPY --chown=xroad:xroad files/override-docker.ini /etc/xroad/conf.d/
COPY --chown=root:root files/ss-xroad.conf /etc/supervisor/conf.d/xroad.conf
CMD ["/root/entrypoint.sh"]

EXPOSE 8080 8443 4000 5500 5577
