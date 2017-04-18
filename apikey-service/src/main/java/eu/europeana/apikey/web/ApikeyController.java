/*
 * Copyright 2007-2017 The Europeana Foundation
 *
 *  Licenced under the EUPL, Version 1.1 (the "Licence") and subsequent versions as approved
 *  by the European Commission;
 *  You may not use this work except in compliance with the Licence.
 *
 *  You may obtain a copy of the Licence at:
 *  http://joinup.ec.europa.eu/software/page/eupl
 *
 *  Unless required by applicable law or agreed to in writing, software distributed under
 *  the Licence is distributed on an "AS IS" basis, without warranties or conditions of
 *  any kind, either express or implied.
 *  See the Licence for the specific language governing permissions and limitations under
 *  the Licence.
 */


/**
 * Created by luthien on 18/04/2017.
 */

package eu.europeana.apikey.web;

import org.joda.time.Duration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.util.StringUtils;
import eu.europeana.apikey.domain.ApiKey;
import eu.europeana.apikey.repos.ApiKeyRepo;
import eu.europeana.apikey.util.ApiName;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;

import javax.validation.Valid;
import java.util.Date;

@RestController
@RequestMapping("/apikey")
public class ApikeyController {

    private final ApiKeyRepo  apiKeyRepo;
    private static final String READ = "read";
    private static final String WRITE = "write";

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

    @RequestMapping(path = "/{id}/validate", method = RequestMethod.POST)
    public ResponseEntity<ApiKey> validate(
            @PathVariable("id") String id,
            @RequestParam(value = "api", required = false) String api,
            @RequestParam(value = "method", required = false) String method) {

        ApiName apiName;
        HttpHeaders headers = new HttpHeaders();
        DateTime nowDtUtc = new DateTime(DateTimeZone.UTC);
        Date now = nowDtUtc.toDate();

        if (!StringUtils.isEmpty(api)) {
            try {
                apiName = ApiName.valueOf(api.toUpperCase().trim());
            } catch (IllegalArgumentException e) {
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
        } else {
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }

        if (!StringUtils.isEmpty(method)) {
            if (!method.equalsIgnoreCase(READ) || method.equalsIgnoreCase(WRITE)){
                return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
            }
        }

        // retrieve apikey & check if available
        ApiKey apikey = this.apiKeyRepo.findOne(id);
        if (null == apikey){
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }

        // check if not deprecated (deprecationDate != null & in the past)
        if (null != apikey.getDeprecationDate() && apikey.getDeprecationDate().before(new Date())){
            return new ResponseEntity<>(HttpStatus.GONE);
        }

        // set activationdate = sysdate if null
        if (null == apikey.getActivationDate()){
            apikey.setActivationDate(now);
        }

        // set lastaccessDate = sysdate
        apikey.setLastaccessDate(now);

        // (mock-)check usage
        long usage = apikey.getUsage();
        long remaining = apikey.getUsageLimit() - usage;
        headers.add("X-RateLimit-Reset", String.valueOf(new Duration(nowDtUtc, nowDtUtc.plusDays(1).withTimeAtStartOfDay()).toStandardSeconds().getSeconds()));

        if (remaining <= 0l){
            // no way, José!
            headers.add("X-RateLimit-Remaining", String.valueOf(0));
            return new ResponseEntity<>(headers, HttpStatus.TOO_MANY_REQUESTS);
        } else {
            // welcome, gringo!
            headers.add("X-RateLimit-Remaining", String.valueOf(remaining - 1));
            apikey.setUsage(usage + 1);
            this.apiKeyRepo.save(apikey);
            return new ResponseEntity<>(headers, HttpStatus.NO_CONTENT);
        }
    }


//    @RequestMapping(path = "/{id}", method = RequestMethod.DELETE)
//    public ResponseEntity<String> delete(@PathVariable("id") Long id) {
//        this.apiKeyRepo.delete(id);
//        return new ResponseEntity<>(HttpStatus.ACCEPTED);
//    }

}
