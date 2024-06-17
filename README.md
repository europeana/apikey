# API-key service

Europeana's API-key service. 
Depends on the Europeana [Keycloak server project](https://github.com/europeana/keycloak-server/)

## License

Licensed under the EUPL V.1.2.

For full details, see [LICENSE.md](LICENSE.md).

## Build
``mvn clean install`` (add ``-DskipTests``) to skip the unit tests during build

## Deployment
1. Generate a Docker image using the project's [Dockerfile](Dockerfile)

2. Configure the application by generating a `apikey.user.properties` file and placing this in the 
[k8s](k8s) folder. After deployment this file will override the settings specified in the `apikey.properties` file
located in the [src/main/resources](src/main/resources) folder. The .gitignore file makes sure the .user.properties file
is never committed.

3. Configure the deployment by setting the proper environment variables specified in the configuration template files
in the [k8s](k8s) folder

4. Deploy to Kubernetes infrastructure
