package eu.europeana.apikey.repos;

import eu.europeana.apikey.domain.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static eu.europeana.apikey.config.ApikeyDefinitions.TO_MIGRATE_KEYCLOAKID;

/**
 * The interface Api key repo.
 */
@Repository
public interface ApiKeyRepo extends JpaRepository<ApiKey, String> {

    /**
     * Find by email optional.
     *
     * @param email the email
     * @return the optional
     */
    Optional<ApiKey> findByEmail(String email);

    /**
     * Find by keycloak id optional.
     *
     * @param keycloakId the keycloak id
     * @return the optional
     */
    Optional<ApiKey> findByKeycloakId(String keycloakId);
    List<ApiKey> findAll();

    /**
     * Find by email and app name list.
     *
     * @param email   the email
     * @param appName the app name
     * @return the list
     */
    List<ApiKey> findByEmailAndAppName(String email, String appName);

    /**
     * Find all keys to migrate list.
     *
     * @return the list
     * @deprecated (The migration feature for all apikeys to Keycloak clients was abandoned)
     */
    @Deprecated(since="version 0.2 to be released late november 2020")
    @Query("SELECT a FROM ApiKey a WHERE (a.keycloakId is null OR a.keycloakId = '" + TO_MIGRATE_KEYCLOAKID + "')")
    List<ApiKey> findAllKeysToMigrate();
}