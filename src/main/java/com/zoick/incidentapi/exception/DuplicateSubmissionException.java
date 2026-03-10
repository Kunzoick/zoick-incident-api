package com.zoick.incidentapi.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;
@ResponseStatus(HttpStatus.CONFLICT)
public class DuplicateSubmissionException extends RuntimeException {
    public DuplicateSubmissionException(String message){
        super(message);
    }
}
