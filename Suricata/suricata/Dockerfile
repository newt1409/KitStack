# Dockerfile for suricata
FROM ubuntu:20.04
ARG APP_VERSION=6.0.5

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

# Updating base image
RUN apt-get update -y && apt-get upgrade -y && \
    # Below required for adding the PPA
    apt-get install -y --no-install-recommends software-properties-common \
    # Installing Recommended Dependencies
    libpcre3 libpcre3-dbg libpcre3-dev build-essential libpcap-dev   \
    libnet1-dev libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev \
    libcap-ng-dev libcap-ng0 make libmagic-dev         \
    libnss3-dev libgeoip-dev liblua5.1-dev libhiredis-dev libevent-dev \
    python-yaml rustc cargo cron logrotate \
    # Installing Dependencies for Rust Support
    rustc cargo && \
    cargo install --force --debug --version 0.14.1 cbindgen && \
    # Adding OISF's Personal Package Archive
    # Suricata Installation
    add-apt-repository ppa:oisf/suricata-stable -y && apt-get update -y && apt-get install -y --no-install-recommends suricata && \
    apt-get remove -y software-properties-common && apt-get clean && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Suricata logrotate rule set
COPY suricata /etc/logrotate.d/suricata
COPY suricata_update_local /usr/local/bin/suricata_update_local
# Copy crontab file
COPY root /var/spool/cron/crontabs/root

# Fixing file permissions
RUN chmod 0644 /etc/logrotate.d/suricata & \
# Updating suricata rules/Sources
    suricata-update update-sources && \
    suricata-update enable-source et/open && \
    suricata-update enable-source oisf/trafficid && \
    suricata-update enable-source sslbl/ja3-fingerprints && \
    suricata-update enable-source ptresearch/attackdetection && \
    suricata-update enable-source sslbl/ssl-fp-blacklist && \
    suricata-update enable-source tgreen/hunting && \
    suricata-update enable-source etnetera/aggressive && \
    suricata-update && \
    mknod /var/log/suricata/eve.json p

# Copy & make executable icdm shell script
#COPY icdm/icdm_check /usr/bin/icdm_check
#RUN chmod +x /usr/bin/icdm_check

# Set Working Directory
WORKDIR /etc/suricata

# Run crontab job
RUN chmod 0644 /var/spool/cron/crontabs/root && crontab /var/spool/cron/crontabs/root

#CMD ["/bin/bash"]
CMD suricata -v -i ens161 -i ens162 -i ens192 -i ens193 -i ens224 -i ens225 -i ens256 -i ens257
