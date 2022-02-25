Make sure to change the settings in the .env file, but definetly change ES_HOST as Fleet needs the host IP due to docker encapsulation

      ES_HOST=<IP>

Everything is dockerized and creates the fleet token automatically

      docker-compose up -d
 
HOWEVER it needs kibana to be restarted to incorperate Fleet setup after initial run, and needs a full docker restart

      docker-compose down
      docker-compose up -d

