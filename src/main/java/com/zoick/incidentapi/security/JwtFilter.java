package com.zoick.incidentapi.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * JWT authentication filter- runs once per request before controllers
 * Per DDR-001-> validates JWT signature and expiry on ever request, extracts userId and role from token claims
 * set authentication in security context if token is valid, never checks tokenVersion and also never touches redis
 * if token is invalid, request is denied
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {
    private static final String AUTHORIZATION_HEADER= "Authorization";
    private static final String BEARER_PREFIX= "Bearer ";
    private static final String CORRELATION_HEADER= "X-Correlation-Id";
    private final JwtUtil jwtUtil;
    private final UserDetailsServiceImpl userDetailsService;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        //extract token form Authorization header
        String token= extractToken(request);
        if(token != null && jwtUtil.isValid(token)){
            authenticateRequest(token, request);
        }else if(token != null){ // token was present but invalid- log for observability
            log.debug("Invalid JWT token | correlationId={} | path={}", request.getAttribute("X-Correlation-Id"), request.getRequestURI());
        }
        //always continue for filter chain, security rules in securityConfig handle unauthorized requests
        filterChain.doFilter(request, response);
    }
    /**
     * sets the authenticated principal in the securityContext, after this runs, the request is treated as authenticated
     * and controllers can access the current user via securityContentHolder or @AuthenticationPrincipal
     */
    private void authenticateRequest(String token, HttpServletRequest request){
        try{
         String userId= jwtUtil.extractUserId(token);
         //only set authentication if not already set
            if(SecurityContextHolder.getContext().getAuthentication() == null){
                UserDetails userDetails=userDetailsService.loadUserByUsername(userId);
                UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }catch (Exception e){
            log.warn("Failed to authenticate request | error={}", e.getMessage());
            SecurityContextHolder.clearContext();
        }
    }
    /**
     * extracts the jwt from the authorization header, returns null if header is missing or not bearer format
     */
    private String extractToken(HttpServletRequest request){
        String header= request.getHeader(AUTHORIZATION_HEADER);
        if(header != null && header.startsWith(BEARER_PREFIX)){
            return header.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}
