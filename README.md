Make sure to change the IP in the .env file, as Fleet needs the host IP due to docker encapsulation

      ES_HOST=<IP>

Everything is dockerized and creates the fleet token automatically

      docker-compose up -d   

*NOTE: The esdata folders created will need their permissions changed after the first run*

      chmod -R 775 esdata* 
