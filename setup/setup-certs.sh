# Exit on Error
set -e

OUTPUT_DIR=/secrets/certs
ZIP_FILE=$OUTPUT_DIR/certs.zip
CA_ZIP_FILE=$OUTPUT_DIR/ca.zip


printf "======= Generating Elastic Stack Certificates =======\n"
printf "=====================================================\n"

if ! command -v unzip &>/dev/null; then
    printf "Installing Necessary Tools... \n"
    yum install -y -q -e 0 unzip;
fi

printf "Clearing Old Certificates if exits... \n"
find $OUTPUT_DIR -mindepth 1 -exec rm -rf -- {} +

#create CA
printf "Generating Certificate Authority (CA)... \n"
bin/elasticsearch-certutil ca <<<$'\n'

printf "Generating Elastic Truststore Certificate... \n"
bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12 <<<$'\n\n\n'

printf "Parsing Elastic CA cert/key from PKCS12 Certificate... \n"
openssl pkcs12 -in elastic-certificates.p12 -out ca.crt -clcerts -nokeys -passin pass:
openssl pkcs12 -in elastic-certificates.p12 -out ca.key -nokeys -nodes -passin pass:

printf "Generating HTTP Certificates... \n"
bin/elasticsearch-certutil http <<<$'n\ny\n/usr/share/elasticsearch/elastic-stack-ca.p12\n\n5y\nn\n*.windomain.local\nlocalhost\n\ny\n10.0.0.198\n127.0.0.1\n\ny\nn\n\n'

printf "Generating Service Certificates... \n"
bin/elasticsearch-certutil cert --ca elastic-stack-ca.p12 --silent --pem --in /setup/instances.yml -out $ZIP_FILE <<<$'\n'
unzip -qq $ZIP_FILE -d $OUTPUT_DIR

cp ca.crt $OUTPUT_DIR/elasticsearch
cp ca.key $OUTPUT_DIR/elasticsearch
cp elastic-stack-ca.p12 $OUTPUT_DIR/elasticsearch
cp elastic-certificates.p12 $OUTPUT_DIR/elasticsearch
cp elasticsearch-ssl-http.zip $OUTPUT_DIR
unzip -qq elasticsearch-ssl-http.zip -d $OUTPUT_DIR

printf "Applying Permissions... \n"
chown -R 1000:0 $OUTPUT_DIR
find $OUTPUT_DIR -type f -exec chmod 655 -- {} +

printf "=====================================================\n"
printf "SSL Certifications generation completed successfully.\n"
printf "=====================================================\n"