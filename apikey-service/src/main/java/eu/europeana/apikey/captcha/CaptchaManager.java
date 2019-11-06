package eu.europeana.apikey.captcha;

import eu.europeana.apikey.domain.ApikeyException;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

@Service
public class CaptchaManager {
    private static final Logger LOG = LogManager.getLogger(CaptchaManager.class);

    @Value("${recaptcha.verification-url.scheme}")
    private String verificationUrlScheme;

    @Value("${recaptcha.verification-url.host}")
    private String verificationUrlHost;

    @Value("${recaptcha.verification-url.path}")
    private String verificationUrlPath;

    @Value("${recaptcha.secret}")
    private String secret;

    private CloseableHttpClient httpClient;

    @PostConstruct
    public void init() {
        httpClient = HttpClients.createDefault();
    }

    /**
     * Verify Captcha token by sending request to the verification URL. Response is a JSON with
     * a field "success" indicating true or false. When it's false "error-codes" field contains
     * reason of failure.
     *
     * @param captchaToken Token to be verified.
     * @return true when verification successful, false when there was problem with verification response
     * @throws ApikeyException when there was false response, exception contains error code
     */
    public boolean verifyCaptchaToken(String captchaToken) throws ApikeyException {
        String verificationResponse = getVerificationResponse(captchaToken);
        LOG.debug("Captcha verification response = {} ", verificationResponse);
        if (verificationResponse != null) {
            JSONObject jsonObject = new JSONObject(verificationResponse);
            if (!jsonObject.getBoolean("success")) {
                JSONArray jsonArray = jsonObject.getJSONArray("error-codes");
                throw new ApikeyException(HttpStatus.SC_FORBIDDEN, jsonArray.get(0).toString());
            }
            return true;
        }
        return false;
    }

    /**
     * Post token in the verification request to the verification URL. Return JSON response or null in case of any exception.
     *
     * @param captchaToken token to be verified
     * @return JSON response from the verification URL or null in case of any exception
     */
    private String getVerificationResponse(String captchaToken) {
        CloseableHttpResponse response = null;
        try {
            HttpPost httpPost = new HttpPost(getVerificationURI(captchaToken));
            LOG.debug("Sending captcha verification...");
            response = httpClient.execute(httpPost);
            LOG.debug("Received captcha verification");
            if (response.getStatusLine().getStatusCode() == org.apache.http.HttpStatus.SC_OK) {
                return IOUtils.toString(response.getEntity().getContent(), "UTF-8");
            }
        } catch (URISyntaxException e) {
            LOG.error("Wrong URI syntax.", e);
        } catch (IOException e) {
            LOG.error("Captcha verification request failed.", e);
        } finally {
            if (response != null) {
                try {
                    response.close();
                } catch (IOException e) {
                    LOG.error("Close response for captcha verification failed.", e);
                }
            }
        }
        return null;
    }


    /**
     * Prepare URI for the request to the verification URL.
     *
     * @param captchaToken token to be used as the parameter.
     * @return URI for the request
     * @throws URISyntaxException
     */
    private URI getVerificationURI(String captchaToken) throws URISyntaxException {
        URIBuilder builder = new URIBuilder();
        builder.setScheme(verificationUrlScheme).setHost(verificationUrlHost).setPath(verificationUrlPath)
                .setParameter("secret", secret)
                .setParameter("response", captchaToken);
        return builder.build();
    }

    @PreDestroy
    public void close() {
        try {
            httpClient.close();
        } catch (IOException e) {
            LOG.warn("Closing httpClient failed", e);
        }
    }
}
