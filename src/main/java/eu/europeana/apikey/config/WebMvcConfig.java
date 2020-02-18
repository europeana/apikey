package eu.europeana.apikey.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.ArrayList;
import java.util.List;

/**
 * Configures Web configuration on all the request
 * @author Srishti Singh
 * Created on 18-02-2020
 */
@Configuration(proxyBeanMethods = false)
public class WebMvcConfig implements WebMvcConfigurer {

    @Override
    public void configureMessageConverters(List<HttpMessageConverter<?>> converters) {
        converters.add(jacksonMessageConverter());
        WebMvcConfigurer.super.configureMessageConverters(converters);
    }

    /**
     * To handle empty content-Type header.
     * Configuration of MappingJackson2HttpMessageConverter to handle application/octet-stream
     *
     * @return messageConverter with application/json, application/*+json and octet-stream
     */
    @Bean
    public MappingJackson2HttpMessageConverter jacksonMessageConverter() {
        MappingJackson2HttpMessageConverter messageConverter = new MappingJackson2HttpMessageConverter();

        List<MediaType> supportedMediaTypes=new ArrayList<>();
        supportedMediaTypes.addAll(messageConverter.getSupportedMediaTypes());
        messageConverter.setSupportedMediaTypes(supportedMediaTypes);
        supportedMediaTypes.add(MediaType.APPLICATION_OCTET_STREAM);
        messageConverter.setSupportedMediaTypes(supportedMediaTypes);
        messageConverter.setPrettyPrint(true);
        return messageConverter;
    }
}
