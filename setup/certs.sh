# Exit on Error
set -e

OUTPUT_DIR=config/certs

printf "\033c"
printf "======= Generating Elastic Stack Certificates =======\n"
printf "=====================================================\n"

#health check bandaid for fleet_token
rm -f setup/fleet.token

if [ ! -d "/startup/esdata" ]; then
    echo "Creating folders for elastic data..."
    mkdir -p /startup/esdata/{esdata01,esdata02,esdata03}
    chmod -R 775 /startup/esdata
fi
if [ -f "$OUTPUT_DIR/ca/ca.crt" ]; then
    echo "Certs Exist skipping..."
    #give time for healthcheck to update
    sleep 10
    exit 0
    else
    echo "Starting Certificate Creation"
fi

printf "Clearing Old Certificates if exits... \n"
find $OUTPUT_DIR -mindepth 1 -exec rm -rf -- {} +

if [ -z $ELASTIC_PASSWORD ]; then
    echo "Set the ELASTIC_PASSWORD environment variable in the .env file"
    exit 1;
elif [ -z $KIBANA_PASSWORD ]; then
    echo "Set the KIBANA_PASSWORD environment variable in the .env file"
    exit 1;
elif [ -z $ES_HOST ]; then
    echo "Set the ES_HOST environment variable in the .env file"
    exit 1;
fi

echo "Elastic password is: $ELASTIC_PASSWORD"
echo "Kibnaa password is: $KIBANA_PASSWORD \n"

echo "\nGenerating Certificate Authority... \n"
bin/elasticsearch-certutil ca --silent --pem -out config/certs/ca.zip;
unzip config/certs/ca.zip -d config/certs

echo "Generating HTTP Certificates... \n"
printf "n\ny\n/usr/share/elasticsearch/config/certs/ca/ca.crt\n/usr/share/elasticsearch/config/certs/ca/ca.key\n\n5y\nn\n${CERT_DOMAIN}\nlocalhost\nkibana\nfleet\n\ny\n${ES_HOST}\n127.0.0.1\n\ny\nn\n\n\n" | elasticsearch-certutil http
#elasticsearch-certutil http <<<$'n\ny\n/usr/share/elasticsearch/config/certs/ca/ca.crt\n/usr/share/elasticsearch/config/certs/ca/ca.key\n\n5y\nn\n*.windomain.local\nlocalhost\nkibana\nfleet\n\ny\n10.0.0.198\n127.0.0.1\n\ny\nn\n\n';
unzip elasticsearch-ssl-http.zip -d config/certs
mv elasticsearch-ssl-http.zip config/certs/.

echo "Creating Service Certificates"
bin/elasticsearch-certutil cert --silent --pem -out config/certs/certs.zip --in /setup/instances.yml --ca-cert config/certs/ca/ca.crt --ca-key config/certs/ca/ca.key
unzip config/certs/certs.zip -d config/certs

echo "Setting file permissions"
chown -R root:root config/certs
find $OUTPUT_DIR -type d -exec chmod -R 750 {} +
find $OUTPUT_DIR -type f -exec chmod -R 640 {} +
echo "All done!"

#give time for healthcheck to update
sleep 10