echo "Prepping Kibana for Fleet Server Integration"
curl -k -s --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" -X POST "http://${ES_HOST}:5601/api/fleet/setup" --header 'kbn-xsrf: true' > /dev/null 2>&1
echo "Creating Fleet Service Token"
rand_key=$(openssl rand -base64 40 | tr -d "=+/" | cut -c1-32)
token=$(curl --insecure -s --cacert config/certs/ca/ca.crt -u "elastic:${ELASTIC_PASSWORD}" -H "Content-Type: application/json" -X POST "https://${ES_HOST}:9200/_security/service/elastic/fleet-server/credential/token/$rand_key" | cut -d ':' -f 5 | cut -d '}' -f 1 | cut -d '"' -f 2)
echo "FLEET_SERVER_SERVICE_TOKEN=$token" > /setup/fleet.token
echo "Fleet token complete"
