echo "Prepping Kibana for Fleet Server Integration"
curl -k -u "elastic:${ELASTIC_PASSWORD}" -X POST http://${ES_HOST}:5601/api/fleet/setup --header 'kbn-xsrf: true'
echo "Creating Fleet Service Token"
rand_key=$(openssl rand -base64 40 | tr -d "=+/" | cut -c1-32)
token=$(curl -s -X POST --cacert config/certs/ca/ca.crt -u elastic:${ELASTIC_PASSWORD} -H "Content-Type: application/json" https://es01:9200/_security/service/elastic/fleet-server/credential/token/$rand_key | cut -d ':' -f 5 | cut -d '}' -f 1 | cut -d '"' -f 2)
#token=`curl -k -u "elastic:${ELASTIC_PASSWORD}" -X POST http://${ES_HOST}:5601/api/fleet/service-tokens --header 'kbn-xsrf: true' | cut -d ':' -f 3 | cut -d '"' -f 2`
echo "FLEET_SERVER_SERVICE_TOKEN=$token" > /setup/fleet.token