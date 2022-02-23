
if [ -f "/setup/fleet.token" ]; then
    echo "Token Exists skipping..."
else
    rand_key=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 12 | head -n 1 )
    echo "Creating Fleet Service Token"
    token=$(curl -s -X POST --cacert config/certs/ca/ca.crt -u elastic:${ELASTIC_PASSWORD} -H "Content-Type: application/json" https://es01:9200/_security/service/elastic/fleet-server/credential/token/$rand_key | cut -d ':' -f 5 | cut -d '}' -f 1 | cut -d '"' -f 2)
    echo "FLEET_SERVER_SERVICE_TOKEN=$token" > /setup/fleet.token
fi
