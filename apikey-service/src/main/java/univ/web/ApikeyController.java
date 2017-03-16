package univ.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import univ.domain.ApiKey;
import univ.repos.ApiKeyRepo;

import javax.validation.Valid;

@RestController
@RequestMapping("/apikey")
public class ApikeyController {

    private final ApiKeyRepo  apiKeyRepo;

    @Autowired
    public ApikeyController(ApiKeyRepo apiKeyRepo) {
        this.apiKeyRepo = apiKeyRepo;
    }

    @RequestMapping(method = RequestMethod.POST)
    public ResponseEntity<ApiKey> save(@RequestBody @Valid ApiKey apikey) {
        ApiKey savedApikey = this.apiKeyRepo.save(apikey);
        return new ResponseEntity<>(savedApikey, HttpStatus.CREATED);
    }

    @RequestMapping(method = RequestMethod.PUT)
    public ResponseEntity<ApiKey> update(@RequestBody @Valid ApiKey apikey) {
        ApiKey savedApikey = this.apiKeyRepo.save(apikey);
        return new ResponseEntity<>(savedApikey, HttpStatus.CREATED);
    }

    @RequestMapping(method = RequestMethod.GET)
    public ResponseEntity<Page<ApiKey>> getPage(Pageable pageable) {
        Page<ApiKey> page = this.apiKeyRepo.findAll(pageable);
        return new ResponseEntity<>(page, HttpStatus.OK);
    }

    @RequestMapping(path = "/{id}", method = RequestMethod.GET)
    public ResponseEntity<ApiKey> get(@PathVariable("id") String id) {
        ApiKey apikey = this.apiKeyRepo.findOne(id);
        return new ResponseEntity<>(apikey, HttpStatus.OK);
    }



//    @RequestMapping(path = "/{id}", method = RequestMethod.DELETE)
//    public ResponseEntity<String> delete(@PathVariable("id") Long id) {
//        this.apiKeyRepo.delete(id);
//        return new ResponseEntity<>(HttpStatus.ACCEPTED);
//    }

}
