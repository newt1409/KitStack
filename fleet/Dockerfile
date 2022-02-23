FROM docker.elastic.co/beats/elastic-agent:8.0.0
  
ARG FLEET_SERVER_ENABLE=1
ARG FLEET_SERVER_INSECURE_HTTP=0
ARG FLEET_INSECURE=1
ARG FLEET_SERVER_SERVICE_TOKEN=""
ARG FLEET_ENROLL=1
ARG FLEET_SERVER_CERT=/usr/share/elastic-agent/cert.crt
ARG FLEET_SERVER_CERT_KEY=/usr/share/elastic-agent/cert.key
ARG FLEET_URL=https://10.0.0.198:8220
ARG FLEET_SERVER_ELASTICSEARCH_HOST=https://10.0.0.198:9200
ARG FLEET_SERVER_ELASTICSEARCH_CA=/usr/share/elastic-agent/ca.pem
ARG KIBANA_FLEET_CA=/usr/share/elastic-agent/ca.pem
ARG FLEET_CA=/usr/share/elastic-agent/ca.pem
ARG ELASTICSEARCH_CA=/usr/share/elastic-agent/ca.pem
ARG KIBANA_CA=/usr/share/elastic-agent/ca.pem

RUN ls -la ../setup/fleet.token
