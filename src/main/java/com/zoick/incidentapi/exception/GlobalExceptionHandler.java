package com.zoick.incidentapi.exception;

import com.zoick.incidentapi.dto.response.ErrorResponse;
import com.zoick.incidentapi.security.CorrelationContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;
import com.zoick.incidentapi.exception.DuplicateSubmissionException;
import com.zoick.incidentapi.exception.TrustBlockedException;
import java.util.HashMap;
import java.util.Map;

/**
 * central exception handler for the entire api, every exception that reaches this class is caught here.
 * Every error is logged with its correlationId so an operator can trace the full request from this log entry alone.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    private static final String CORRELATION_HEADER= "X-Correlation-Id";
    //validation errors

    /**
     * handles @valid failures on request bodies, return field-level breakdown of what failed
     * @param ex
     * @param request
     * @return
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidation(MethodArgumentNotValidException ex,  HttpServletRequest request){
        Map<String, String> fieldErrors= new HashMap<>();
        for(FieldError fieldError : ex.getBindingResult().getFieldErrors()){
            fieldErrors.put(fieldError.getField(), fieldError.getDefaultMessage());
        }
        String correlationId= getCorrelationId(request);
        log.warn("Validation failed | path={} | correlationId={} | fields={}", request.getRequestURI(),
                correlationId, fieldErrors);
        return ResponseEntity.badRequest().body(ErrorResponse.ofValidation(request.getRequestURI(),
                correlationId, fieldErrors));
    }
    // security errors
    /**
     * handles authorization faliures. return 403 access-denied, never returns 404 for resource ownership
     * -> that reveals the resource exists
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(AccessDeniedException exception,  HttpServletRequest request){
        String correlationId= getCorrelationId(request);
        log.warn("Access denied | path={} | correlationId={}", request.getRequestURI(), correlationId);
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(ErrorResponse.of(403, "ACCESS_DENIED",
                "You do not have permission to access this resource.", request.getRequestURI(), correlationId));
    }
    /**
     * handles locked account during authentication
     * returns 403 account-locked
     */
    @ExceptionHandler(LockedException.class)
    public ResponseEntity<ErrorResponse> handleLocked(
            LockedException ex,
            HttpServletRequest request
    ) {
        String correlationId = getCorrelationId(request);
        log.warn("Locked account login attempt | path={} | correlationId={}",
                request.getRequestURI(), correlationId);

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of(
                        403,
                        "ACCOUNT_LOCKED",
                        "This account has been locked. Contact support.",
                        request.getRequestURI(),
                        correlationId
                ));
    }
    /**
     * Handles bad credentials during authentication.
     * Returns 401 INVALID_CREDENTIALS.
     * Intentionally vague — never reveal which field was wrong.
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
            BadCredentialsException ex,
            HttpServletRequest request
    ) {
        String correlationId = getCorrelationId(request);
        log.warn("Bad credentials | path={} | correlationId={}",
                request.getRequestURI(), correlationId);

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(ErrorResponse.of(
                        401,
                        "INVALID_CREDENTIALS",
                        "Invalid email or password.",
                        request.getRequestURI(),
                        correlationId
                ));
    }
    /**
     * Handles disabled accounts.
     * Returns 403 ACCOUNT_DISABLED.
     */
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ErrorResponse> handleDisabled(
            DisabledException ex,
            HttpServletRequest request
    ) {
        String correlationId = getCorrelationId(request);
        log.warn("Disabled account login attempt | path={} | correlationId={}",
                request.getRequestURI(), correlationId);

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of(
                        403,
                        "ACCOUNT_DISABLED",
                        "This account has been disabled.",
                        request.getRequestURI(),
                        correlationId
                ));
    }
    //Application errors
    /**
     * Handles 404 — resource genuinely does not exist.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNotFound(
            NoResourceFoundException ex,
            HttpServletRequest request
    ) {
        String correlationId = getCorrelationId(request);
        log.debug("Resource not found | path={} | correlationId={}",
                request.getRequestURI(), correlationId);

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ErrorResponse.of(
                        404,
                        "RESOURCE_NOT_FOUND",
                        "The requested resource does not exist.",
                        request.getRequestURI(),
                        correlationId
                ));
    }
    @ExceptionHandler(TrustBlockedException.class)
    public ResponseEntity<ErrorResponse> handleTrustBlocked(
            TrustBlockedException ex,
            HttpServletRequest request
    ) {
        String correlationId = getCorrelationId(request);
        log.warn("Trust blocked | path={} | correlationId={}",
                request.getRequestURI(), correlationId);

        return ResponseEntity
                .status(HttpStatus.FORBIDDEN)
                .body(ErrorResponse.of(
                        403,
                        "TRUST_BLOCKED",
                        ex.getMessage(),
                        request.getRequestURI(),
                        correlationId
                ));
    }

    @ExceptionHandler(DuplicateSubmissionException.class)
    public ResponseEntity<ErrorResponse> handleDuplicate(
            DuplicateSubmissionException ex,
            HttpServletRequest request
    ) {
        String correlationId = getCorrelationId(request);
        log.warn("Duplicate submission | path={} | correlationId={}",
                request.getRequestURI(), correlationId);

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ErrorResponse.of(
                        409,
                        "DUPLICATE_SUBMISSION",
                        ex.getMessage(),
                        request.getRequestURI(),
                        correlationId
                ));
    }
    //catch all
    /**
     * Catches everything else.
     * Returns 500 INTERNAL_ERROR.
     *
     * CRITICAL: the exception message and stack trace are
     * logged for operators but NEVER sent to the client.
     * Internal detail stays internal — always.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleAll(
            Exception ex,
            HttpServletRequest request
    ) {
        String correlationId = getCorrelationId(request);
        log.error("Unhandled exception | path={} | correlationId={} | error={}",
                request.getRequestURI(), correlationId, ex.getMessage(), ex);

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of(
                        500,
                        "INTERNAL_ERROR",
                        "An unexpected error occurred. Please try again later.",
                        request.getRequestURI(),
                        correlationId
                ));
    }
    //helper
    /**
     * extracts the correlation ID from the request header, returns "unknown if not present->
     * which means the correlation filter has not run yet
     */
    private String getCorrelationId(HttpServletRequest request){
        Object attribute= request.getAttribute(CORRELATION_HEADER);
        if(attribute != null) return attribute.toString();
        return CorrelationContext.get();
    }
}
