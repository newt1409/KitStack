FROM alpine:3.14
#
# Include dist
ADD dist/ /root/dist/
#
# Install packages
RUN apk -U --no-cache add \
                 ca-certificates \
                 curl \
                 file \
		 hiredis \
                 libcap \
                 wget \
                 suricata && \
#
# Setup user, groups and configs
    addgroup -g 2000 suri && \
    adduser -S -H -u 2000 -D -g 2000 suri && \
    chmod 644 /etc/suricata/*.config && \
    cp /root/dist/*.yaml /etc/suricata/ && \
    cp /root/dist/*.conf /etc/suricata/ && \
    cp /root/dist/*.bpf /etc/suricata/ && \
#
# Download the latest EmergingThreats OPEN ruleset
    cp /root/dist/update.sh /usr/bin/ && \
    chmod 755 /usr/bin/update.sh && \
    suricata-update update-sources && \
    suricata-update --no-reload && \
    suricata-update enable-source et/open && \
    suricata-update enable-source oisf/trafficid && \
    suricata-update enable-source sslbl/ja3-fingerprints && \
    suricata-update enable-source ptresearch/attackdetection && \
    suricata-update enable-source sslbl/ssl-fp-blacklist && \
    suricata-update enable-source tgreen/hunting && \
    suricata-update enable-source etnetera/aggressive && \
#
# Clean up
    rm -rf /root/* && \
    rm -rf /tmp/* && \
    rm -rf /var/cache/apk/*
#
# Start suricata
STOPSIGNAL SIGINT
#CMD SURICATA_CAPTURE_FILTER=$(update.sh $OINKCODE) && exec suricata -v -F $SURICATA_CAPTURE_FILTER -i ens33 -i ens160 -i ens192 -i ens224
CMD SURICATA_CAPTURE_FILTER=$(update.sh $OINKCODE) && exec suricata -v -F $SURICATA_CAPTURE_FILTER -i ens161 -i ens162 -i ens192 -i ens193 -i ens224 -i ens225 -i ens256 -i ens257