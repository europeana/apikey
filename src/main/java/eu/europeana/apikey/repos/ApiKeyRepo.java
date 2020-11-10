package eu.europeana.apikey.repos;

import eu.europeana.apikey.domain.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static eu.europeana.apikey.config.ApikeyDefinitions.TO_MIGRATE_KEYCLOAKID;

@Repository
public interface ApiKeyRepo extends JpaRepository<ApiKey, String> {

    Optional<ApiKey> findByEmail(String email);
    Optional<ApiKey> findByKeycloakId(String keycloakId);
    List<ApiKey> findAll();
    List<ApiKey> findByEmailAndAppName(String email, String appName);

    @Query("SELECT a FROM ApiKey a WHERE (a.keycloakId is null OR a.keycloakId = '" + TO_MIGRATE_KEYCLOAKID + "')")
    List<ApiKey> findAllKeysToMigrate();
}