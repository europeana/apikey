package eu.europeana.apikey.repos;

import eu.europeana.apikey.domain.Apikey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ApikeyRepo extends JpaRepository<Apikey, String> {
    Optional<Apikey> findByEmail(String apikey);
}