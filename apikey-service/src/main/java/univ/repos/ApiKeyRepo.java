package univ.repos;

import org.springframework.data.jpa.repository.JpaRepository;
import univ.domain.ApiKey;

import java.util.Optional;

public interface ApiKeyRepo extends JpaRepository<ApiKey, String> {
    Optional<ApiKey> findByEmail(String apikey);
}