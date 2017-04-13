package eu.europeana.apikey.repos;

import eu.europeana.apikey.domain.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ApiKeyRepo extends JpaRepository<ApiKey, String> {
    Optional<ApiKey> findByEmail(String apikey);
}