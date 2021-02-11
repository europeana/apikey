package eu.europeana.apikey.keycloak;

import eu.europeana.api.commons.error.EuropeanaGlobalExceptionHandler;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Class to handle custom error handling for spring security exceptions
 * @author Srishti Singh 11-Feb-2021
 */
public class CustomEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        EuropeanaGlobalExceptionHandler europeanaGlobalExceptionHandler = new EuropeanaGlobalExceptionHandler();
        europeanaGlobalExceptionHandler.handleAuthenticationError(e, httpServletRequest, httpServletResponse);
    }
}
