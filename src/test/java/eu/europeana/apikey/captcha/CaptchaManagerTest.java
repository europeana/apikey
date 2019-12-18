package eu.europeana.apikey.captcha;

import eu.europeana.apikey.exception.ApikeyException;
import org.apache.http.HttpEntity;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.exceptions.misusing.InvalidUseOfMatchersException;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.modules.junit4.PowerMockRunner;
import org.powermock.modules.junit4.PowerMockRunnerDelegate;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;

@RunWith(PowerMockRunner.class)
@PowerMockRunnerDelegate(JUnit4.class)
@PowerMockIgnore("javax.management.*")
public class CaptchaManagerTest {

    private static final String UNSUCCESSFUL_RESPONSE =
            "{\"success\": false,\"error-codes\": [\"invalid-input-response\"]}";

    private static final String SUCCESSFUL_RESPONSE =
            "{\"success\": true,\"error-codes\": []}";

    private static final String CAPTCHA_TOKEN = "token";

    @Mock
    private CloseableHttpClient httpClient;

    @InjectMocks
    private CaptchaManager captchaManager = new CaptchaManager();

    @Before
    public void init() {
        ReflectionTestUtils.setField(captchaManager, "verificationUrlScheme", "https");
        ReflectionTestUtils.setField(captchaManager, "verificationUrlHost", "google.com");
        ReflectionTestUtils.setField(captchaManager, "verificationUrlPath", "verify");
        ReflectionTestUtils.setField(captchaManager, "secret", "secret");
    }

    @Test
    public void verifyCaptchaTokenWhenOK() throws IOException, ApikeyException {
        prepareForTest(true);

        Assert.assertTrue(captchaManager.verifyCaptchaToken(CAPTCHA_TOKEN));
    }

    @Test(expected = ApikeyException.class)
    public void verifyCaptchaTokenWhenFalse() throws IOException, ApikeyException {
        prepareForTest(false);

        captchaManager.verifyCaptchaToken(CAPTCHA_TOKEN);
    }

    @Test
    public void verifyCaptchaTokenWhenNull() throws IOException, ApikeyException {
        prepareForNullVerificationResponse();

        Assert.assertFalse(captchaManager.verifyCaptchaToken(CAPTCHA_TOKEN));
    }

    private void prepareForNullVerificationResponse() throws IOException {
        CloseableHttpResponse postResponse = Mockito.mock(CloseableHttpResponse.class);
        StatusLine postStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(postResponse.getStatusLine()).thenReturn(postStatusLine);
        Mockito.when(postStatusLine.getStatusCode()).thenReturn(400);
        Mockito.when(httpClient.execute(Mockito.anyObject())).thenAnswer(
                invocation -> {
                    Object argument = invocation.getArguments()[0];
                    if (argument instanceof HttpPost) {
                        return postResponse;
                    }
                    throw new InvalidUseOfMatchersException(
                            String.format("Argument %s does not match", argument)
                    );
                });

    }

    private void prepareForTest(boolean success) throws IOException {
        CloseableHttpResponse postResponse = Mockito.mock(CloseableHttpResponse.class);
        StatusLine postStatusLine = Mockito.mock(StatusLine.class);
        Mockito.when(postResponse.getStatusLine()).thenReturn(postStatusLine);
        Mockito.when(postStatusLine.getStatusCode()).thenReturn(200);
        HttpEntity postEntity = Mockito.mock(HttpEntity.class);
        Mockito.when(postResponse.getEntity()).thenReturn(postEntity);
        if (success) {
            Mockito.when(postEntity.getContent()).thenReturn(new ByteArrayInputStream(SUCCESSFUL_RESPONSE.getBytes(Charset.forName("UTF-8"))));
        } else {
            Mockito.when(postEntity.getContent()).thenReturn(new ByteArrayInputStream(UNSUCCESSFUL_RESPONSE.getBytes(Charset.forName("UTF-8"))));
        }
        Mockito.when(httpClient.execute(Mockito.anyObject())).thenAnswer(
                invocation -> {
                    Object argument = invocation.getArguments()[0];
                    if (argument instanceof HttpPost) {
                        return postResponse;
                    }
                    throw new InvalidUseOfMatchersException(
                            String.format("Argument %s does not match", argument)
                    );
                });

    }
}