# Exit on Error
set -e

# Setting Bootstrap Password
echo "Setting bootstrap.password..."
#(echo "$ELASTIC_PASSWORD" | elasticsearch-keystore add -x 'bootstrap.password')
elasticsearch-keystore add -x 'bootstrap.password' <<<$'y\n$ELASTIC_PASSWORD'

# Setting up password for system accounts
#echo "Setting password for system accounts..."
#elasticsearch-setup-passwords interactive <<<$'y\npassword\npassword\npassword\npassword\npassword\npassword\npassword\npassword\npassword\npassword\n'


# ----- Setting Secrets

## Add Additional Config
# 1- Copy the below commented block, uncomment it, and replace <name>, <key>, and <KEY_ENV_VALUE>.
# 2- Pass <KEY_ENV_VALUE> to setup container in `docker-compose-setup.yml`

## Setting <name>
#echo "Setting <name>..."
#(echo "$<KEY_ENV_VALUE>" | elasticsearch-keystore add -x '<key>')


# ----- Setting S3 Secrets

## Setting S3 Access Key
#echo "Setting S3 Access Key..."
#(echo "$AWS_ACCESS_KEY_ID" | elasticsearch-keystore add -x 's3.client.default.access_key')
#
## Setting S3 Secret Key
#echo "Setting S3 Secret Key..."
#(echo "$AWS_SECRET_ACCESS_KEY" | elasticsearch-keystore add -x 's3.client.default.secret_key')