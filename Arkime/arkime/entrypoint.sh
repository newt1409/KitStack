#!/bin/bash


# change config.ini with docker variables, since ini files dont take environment variables...AND sed -i is having issues so save to a file and overwrite
sed "s#.*elasticsearch=h.*#elasticsearch=https://$ELASTIC_USERNAME:$ELASTIC_PASSWORD@localhost:9200#" /opt/arkime/etc/config.ini > config.tmp
cat config.tmp > /opt/arkime/etc/config.ini
sed "s#.*interface=.*#interface=ens192#" /opt/arkime/etc/config.ini > config.tmp
cat config.tmp > /opt/arkime/etc/config.ini

echo "Checking for database initialization"
if [ -f /opt/arkime/etc/db_version ]; then
	verFound=$(grep -c "DB Version" /opt/arkime/etc/db_version )
	if [ $verFound == 0 ]
	then
		echo INIT | /opt/arkime/db/db.pl --insecure --esuser $ELASTIC_USERNAME:$ELASTIC_PASSWORD https://localhost:9200 init
		/opt/arkime/bin/arkime_add_user.sh admin "Admin User" password --admin
		/opt/arkime/db/db.pl --insecure --esuser $ELASTIC_USERNAME:$ELASTIC_PASSWORD https://localhost:9200 info | grep -i 'db version' > /opt/arkime/etc/db_version
	else
		echo "Checking for version changes"
		# possible update
		read old_ver < /opt/arkime/etc/db_version
		new_ver=$(/opt/arkime/db/db.pl --insecure --esuser $ELASTIC_USERNAME:$ELASTIC_PASSWORD https://localhost:9200 info | grep -i 'db version')
		# detect the newer version
		#newer_ver=`echo -e "$old_ver\n$ARKIME_VERSION" | sort -rV | head -n 1`
		# the old version should not be the same as the newer version
		# otherwise -> upgrade
		if [[ ! $old_ver == $newer_ver ]]; then
			echo "Upgrading Elastic database..."
			#echo -e "no\nno" | /opt/arkime/bin/Configure
			/opt/arkime/db/db.pl --insecure --esuser $ELASTIC_USERNAME:$ELASTIC_PASSWORD https://localhost:9200 upgradenoprompt
			/opt/arkime/db/db.pl --insecure --esuser $ELASTIC_USERNAME:$ELASTIC_PASSWORD https://localhost:9200 info | grep -i 'db version' > /opt/arkime/etc/db_version
		else
			echo "No ugrade Needed"
		fi		
	fi
else
	echo "no database file...shrugs?"
	exit
fi

# Start WISE service.
echo "Starting WISE tagger."
# This command seems to need to be run from the directory itself. During testing it wouldn't run properly unless you cd to the directory.
/bin/bash -c 'cd /opt/arkime/wiseService; /opt/arkime/bin/node wiseService.js --webconfig &'
sleep 5

# Start Capture service
echo "Starting arkime-capture."
/bin/bash -c "/opt/arkime/bin/capture --insecure -c /opt/arkime/etc/config.ini --host $HOSTNAME >> /opt/arkime/logs/capture.log 2>&1 &"


# Start Viewer service.
echo "Starting arkime-viewer."
cd /opt/arkime/viewer
/bin/bash -c "/opt/arkime/bin/node viewer.js --insecure -c /opt/arkime/etc/config.ini >> /opt/arkime/logs/viewer.log 2>&1"
