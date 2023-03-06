ARG APP_VERSION=5.0.6
FROM zeek/zeek:${APP_VERSION}

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# Installing Dependencies
RUN apt-get update -y && apt-get install -y --no-install-recommends g++ cmake make libpcap-dev libssl-dev libmaxminddb-dev tzdata cron curl && \
    apt-get clean && apt-get autoremove -y && rm -rf /var/lib/apt/lists/* && \
# Downloading GeoIP database
    curl -L -o /tmp/GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=lvuC9OMJhHaEDSvW&suffix=tar.gz" && \
    curl -L -o /tmp/GeoLite2-ASN.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=lvuC9OMJhHaEDSvW&suffix=tar.gz" && \
    mkdir /var/lib/GeoIP && \
    tar -ztf /tmp/GeoLite2-Country.tar.gz | grep mmdb | xargs -I X tar -Ozxf /tmp/GeoLite2-Country.tar.gz X >> /var/lib/GeoIP/GeoLite2-Country.mmdb && \
    tar -ztf /tmp/GeoLite2-ASN.tar.gz | grep mmdb | xargs -I X tar -Ozxf /tmp/GeoLite2-ASN.tar.gz X >> /var/lib/GeoIP/GeoLite2-ASN.mmdb && \
    rm -rf /tmp/GeoLite2-*


# Installing BZAR and JA3 ZEEK Plugins
RUN zkg install zeek/salesforce/ja3 --force && \
    zkg install zeek/salesforce/hassh --force && \
    zkg install zeek/corelight/zeek-community-id --force && \
    zkg install zeek-af_packet-plugin --force && \
    zkg install https://github.com/Sithari/icmp-exfil-detection --force

# Enabling installed zkg packages and loading scripts
RUN sed -i "s|# @load packages|@load packages|g" /usr/local/zeek/share/zeek/site/local.zeek && \
    echo "@load protocols/smb/log-cmds.zeek" >> /usr/local/zeek/share/zeek/site/local.zeek && \
    echo "@load policy/tuning/json-logs.zeek" >> /usr/local/zeek/share/zeek/site/local.zeek && \
    echo "@load /usr/local/zeek/share/zeek/site/custom_scripts/mitre-bzar" >> /usr/local/zeek/share/zeek/site/local.zeek && \
    echo "@load /usr/local/zeek/share/zeek/site/custom_scripts/multithreaded-exfil-detection" >> /usr/local/zeek/share/zeek/site/local.zeek && \
    sed -i "s|@load frameworks/files/detect-MHR|# @load frameworks/files/detect-MHR|g" /usr/local/zeek/share/zeek/site/local.zeek && \
    echo "@load config.zeek" >> /usr/local/zeek/share/zeek/site/local.zeek && \
    touch /usr/local/zeek/share/zeek/site/config.zeek

COPY plugins  /usr/local/zeek/share/zeek/site/custom_scripts

# Cronjob for Zeek
RUN echo "*/5 * * * * zeekctl cron" > /var/spool/cron/crontabs/root && \
    crontab /var/spool/cron/crontabs/root

COPY docker-entrypoint.sh /docker-entrypoint.sh
CMD ["/docker-entrypoint.sh"]
