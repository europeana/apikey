package eu.europeana.apikey.repos;

import eu.europeana.apikey.domain.Apikey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ApikeyRepo extends JpaRepository<Apikey, String> {

    Optional<Apikey> findByEmail(String apikey);
    public List<Apikey> findAll();
}