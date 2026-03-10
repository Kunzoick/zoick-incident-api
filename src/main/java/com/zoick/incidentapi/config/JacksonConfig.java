package com.zoick.incidentapi.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * jackson configuration-> controls how api serializes and deserializes JSON globally
 * critical: localDateTime and other java 8 data types must serialize as ISO-8601 strings not arrays
 */
@Configuration
public class JacksonConfig {
    @Bean
    public ObjectMapper objectMapper(){
        ObjectMapper mapper= new ObjectMapper();
        mapper.registerModule(new JavaTimeModule());// register java  8 data/time
        mapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        return mapper;
    }
}
