package com.zoick.incidentapi.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.FORBIDDEN)
public class TrustBlockedException extends RuntimeException{
    public TrustBlockedException(String message){
        super(message);
    }
}
