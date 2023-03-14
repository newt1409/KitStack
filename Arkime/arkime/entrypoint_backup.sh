#!/bin/bash

# This section copies the config to a new location, replaces the interface value to the value held in the .env file and copies it back.
#cp /opt/arkime/etc/config.ini /opt/arkime/etc/config.ini.new
#sed -i 's/interface=.*$/interface=$INTERFACE/g' /opt/arkime/etc/config.ini.new
#cp -f /opt/arkime/etc/config.ini.new /opt/arkime/etc/config.ini

# change config.ini with docker variables, since ini files dont take environment variables...AND sed -i is having issues so save to a file and overwrite
sed "s#.*elasticsearch=h.*#elasticsearch=https://$ELASTIC_USERNAME:$ELASTIC_PASSWORD@localhost:9200#" /opt/arkime/etc/config.ini > config.tmp
cat config.tmp > /opt/arkime/etc/config.ini
sed "s#.*interface=.*#interface=ens192#" /opt/arkime/etc/config.ini > config.tmp
cat config.tmp > /opt/arkime/etc/config.ini

if [ "$INIT" == "TRUE" ]
then
  # Initialize Elasticsearch for Arkime data.
  echo "Initializing elasticsearch database."
  echo WIPE | /opt/arkime/db/db.pl --insecure --esuser $ELASTIC_USERNAME:$ELASTIC_PASSWORD https://localhost:9200 wipe
fi

# Start WISE service.
echo "Starting WISE tagger."
# This command seems to need to be run from the directory itself. During testing it wouldn't run properly unless you cd to the directory.
/bin/bash -c 'cd /opt/arkime/wiseService; /opt/arkime/bin/node wiseService.js --webconfig &'
sleep 5

if [ "$CAPTURE" == "TRUE" ]
then
  # Start Capture service
  echo "Starting arkime-capture."
  /bin/bash -c "/opt/arkime/bin/capture --insecure -c /opt/arkime/etc/config.ini --host $HOSTNAME >> /opt/arkime/logs/capture.log 2>&1 &"
fi

# Start Viewer service.
echo "Starting arkime-viewer."
cd /opt/arkime/viewer
/bin/bash -c "/opt/arkime/bin/node viewer.js --insecure -c /opt/arkime/etc/config.ini >> /opt/arkime/logs/viewer.log 2>&1"
