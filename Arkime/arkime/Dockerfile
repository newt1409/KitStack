FROM ubuntu:20.04
ARG APP_VERSION=4.0.2


ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# Installing Dependencies
RUN apt-get update -y && apt-get install -y --no-install-recommends vim python3 python3-pip curl jq libmagic-dev && \
# Installing Arkime
    curl -o /tmp/arkime.deb "https://s3.amazonaws.com/files.molo.ch/builds/ubuntu-20.04/arkime_${APP_VERSION}-1_amd64.deb" && \
    apt-get install -y --no-install-recommends /tmp/arkime.deb && \
    rm -f /tmp/arkime.deb  && apt-get clean && apt-get autoremove -y && rm -rf "/var/lib/apt/lists/*" && \
# Pull maxmind Geo info for countries
    curl -L -o /tmp/GeoLite2-Country.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=lvuC9OMJhHaEDSvW&suffix=tar.gz" && \
    curl -L -o /tmp/GeoLite2-ASN.tar.gz "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=lvuC9OMJhHaEDSvW&suffix=tar.gz" && \
    curl -L -o /opt/arkime/etc/ipv4-address-space.csv "https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv" && \
    # Untar and load into arkime folder
    tar -ztf /tmp/GeoLite2-Country.tar.gz | grep mmdb | xargs -I X tar -Ozxf /tmp/GeoLite2-Country.tar.gz X >> /opt/arkime/etc/GeoLite2-Country.mmdb && \
    tar -ztf /tmp/GeoLite2-ASN.tar.gz | grep mmdb | xargs -I X tar -Ozxf /tmp/GeoLite2-ASN.tar.gz X >> /opt/arkime/etc/GeoLite2-ASN.mmdb && \
    rm -rf "/tmp/GeoLite2-*" && \
# For MAC ADDRESS info
    curl -L -o /opt/arkime/etc/oui.txt "https://raw.githubusercontent.com/wireshark/wireshark/master/manuf" && \
    # Create tags folder
    mkdir /opt/arkime/tags/

# Copy lua script parsers
#COPY lua/dcerpc.lua /opt/arkime/lua/dcerpc.lua
#COPY lua/smb.lua /opt/arkime/lua/smb.lua
COPY lua/entropy.lua /opt/arkime/lua/entropy.lua

# Copy wise's config file
COPY wise/wiseService.ini /opt/arkime/etc/wiseService.ini

# Copy arkime's config file
COPY config/config.ini /opt/arkime/etc/config.ini

# Copy & make executable icdm shell script
COPY icdm/icdm_check /usr/bin/icdm_check
COPY entrypoint.sh /usr/bin/entrypoint
RUN chmod +x /usr/bin/icdm_check /usr/bin/entrypoint

# Set Working Directory
WORKDIR /opt/arkime/viewer
ENTRYPOINT ["/usr/bin/entrypoint"]
