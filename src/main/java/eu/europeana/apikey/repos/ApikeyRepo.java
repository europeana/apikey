package eu.europeana.apikey.repos;

import eu.europeana.apikey.domain.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ApikeyRepo extends JpaRepository<ApiKey, String> {

    Optional<ApiKey> findByEmail(String apikey);
    Optional<ApiKey> findByKeycloakId(String keycloakId);
    public List<ApiKey> findAll();
    public List<ApiKey> findByEmailAndAppName(String email, String appName);
}