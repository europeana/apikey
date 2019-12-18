# Ye Olde Readme 

This i̶s̶  was a Spring Boot based skeleton for connecting to a Postgresql database when deploying to Cloud Foundry.

## DEMO time! 
Local only for now, CF will follow shortly.

1: have Postgres installed with the Apikey table present and filled with at least one record
2: check this thing out
3: navigate to the apikey directory
4: type 

----
mvn spring-boot:run
----

5: enjoy http://localhost:8081/apikey !

## Nota Bene 
If you want to use the postgresql from the api docker then you have to change the server.port configuration in the
src/main/resources/application.yml file