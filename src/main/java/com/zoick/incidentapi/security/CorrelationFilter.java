package com.zoick.incidentapi.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * correlation Id filter-> runs before everything else, including Spring Security.
 * Registered as a raw servlet filter via FilterRegistrationBean in securityConfig
 * RESPONSIBILITIES: generate a unique correlation ID for every request
 * set it as a request attribute(X-Correlation-id) so all downstream components (filters, services, exception handlers) can read it
 * set it as a response header so callers can trace their request in logs
 *
 * if the caller supplies an X_correlation-id header, we honour it. this supports disturbuted tracing where an upstream service propagates its ID.
 */
@Slf4j
public class CorrelationFilter extends OncePerRequestFilter {
    private static final String CORRELATION_ID_HEADER= "X-Correlation-Id";
    private static final String CORRELATION_ID_ATTRIBUTE= "X-Correlation-Id";
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
        throws ServletException, IOException{
        String correlationId= resolveCorrelation(request);
        //make available to all downstream components via request attribute
        request.setAttribute(CORRELATION_ID_ATTRIBUTE, correlationId);
        //return to caller in response header for end-end tracing
        response.setHeader(CORRELATION_ID_HEADER, correlationId);
        CorrelationContext.set(correlationId);
        try{
            filterChain.doFilter(request, response);
        }finally {
            CorrelationContext.clear();//this prevents thread pool leak
        }
    }
    //honour caller-supplied correlation ID if present-> supports distributed tracing, generate a new UUID otherwise
    private String resolveCorrelation(HttpServletRequest request){
        String incoming= request.getHeader(CORRELATION_ID_HEADER);
        return (incoming != null && !incoming.isBlank()) ? incoming : UUID.randomUUID().toString();
    }
    @Override
    protected boolean shouldNotFilterErrorDispatch(){
        return true;
    }
}
