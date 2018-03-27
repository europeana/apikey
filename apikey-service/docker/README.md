#Using the Dockerized sitemap development environment

You can use docker to quickly setup an API key test environment. The docker environment consists a Tomcat server
(Postgresql isn't dockerized yet)

We assume you have Docker already installed on your computer. You need docker-compose version 1.8.0 or later to 
be able to run it ([installation instructions here](https://github.com/docker/compose/releases)).

Remember to configure the apikey-service/src/main/resources/application.yml to point to your postgresql database 

##Starting docker
- Go to the docker folder and execute the command: `docker-compose up`
- After startup the Tomcat server is available at http://localhost:8081
- To test run http://localhost:8081/apikey/apikey/ApiKeyDemo 

##Usage:
 - If you press <kbd>Ctrl</kbd>+<kbd>C</kbd> in the terminal then docker will stop, preserving your current containers. You can restart by
   executing docker-compose up again. If you want to do a clean start you can throw your old containers away first with
   this command: `docker rm docker_apikey-appserver_1`
 - For debugging use Java/Tomcat port = 8000


##Favorite Docker commands:

**Start all API containers**: docker-compose up

**View all running containers**:
docker ps

**Restart Tomcat API application**:
docker restart docker_appserver_1

**Start all API containers in detached mode**:
docker-compose up -d

**Build all images**:
docker-compose build

**Shutdown and remove containers**:
docker-compose down

**Open bash inside a container**:
docker exec -i -t docker_relational-database_1 /bin/bash
