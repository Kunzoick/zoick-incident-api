package com.zoick.incidentapi.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;
import lombok.Getter;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * standard error response shape for all error cases
 * every error this api returns looks exactly like this
 */
@Getter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ErrorResponse {
    private int status;
    private String error;
    private String message;
    private String path;
    private LocalDateTime timestamp;
    private String correlationId;

    /**
     * Field-level validation errors.
     * Only populated on 400 VALIDATION_ERROR responses.
     * Key= field name, Value= error message for all field
     * null on all other error types- excluded from JSON by @jsonInclude.
     */
    private Map<String, String> fieldErrors;
    public static ErrorResponse of(int status, String error, String message, String path, String correlationId){
        return ErrorResponse.builder().status(status).error(error).message(message).path(path).timestamp(LocalDateTime.now())
                .correlationId(correlationId).build();
    }
    public static ErrorResponse ofValidation(String path, String correlationId, Map<String, String> fieldErrors){
        return ErrorResponse.builder().status(400).error("VALIDATION_ERROR").message("Request validation failed. Check fieldErrors for details.")
                .path(path).timestamp(LocalDateTime.now()).correlationId(correlationId).fieldErrors(fieldErrors).build();
    }
}
