FIRST OFF: FLeet is the worst, just the worst

Make sure to change the settings in the .env file, but definetly change ES_HOST as Fleet needs the host IP due to docker encapsulation

      ES_HOST=<IP>

Everything is dockerized and creates the fleet token automagically

      docker-compose up -d
 
HOWEVER it needs kibana to be restarted to incorperate Fleet setup after initial run, and needs a full docker restart

      docker-compose down
      docker-compose up -d

And to fully hack the matrix, tear it down and back up again and you're Neo...some people call it the contra code (up, down, up, down, left, right, etc)

      docker-compose down
      docker-compose up -d
      
     
Common Errors:

Couldnt find the env file: setup/fleet.token
     
      touch setup/fleet.token
