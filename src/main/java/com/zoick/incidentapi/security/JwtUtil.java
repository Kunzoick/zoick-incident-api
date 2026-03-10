package com.zoick.incidentapi.security;

import com.zoick.incidentapi.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.UUID;

/**
 * JwtUtil class for generating and validating JWT tokens.
 * from DDR-001: access tokens are JWT, 5mins ttl
 * claims: useid, role, tokenVersion, signed with HS256
 * this class never touches refresh tokens, those are opaque UUIDs stored hashed in the db
 */
@Slf4j
@Component
public class JwtUtil { // this creates access tokens & validates them
    private final SecretKey signingKey;
    private final long accessTokenExpiryMs;

    public JwtUtil(@Value("${jwt.secret}") String secret,
                   @Value("${jwt.access-token-expiry-ms}") long accessTokenExpiryMs){ // pulls values from application.yaml(jwt.secret-> used to sign tokens) & (jwt.access-token-expiry-ms->how long access tokens last)
        this.signingKey= Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)); // converts the string secret to a cryptographic key(cause jwt signature requires HMAC key)
        this.accessTokenExpiryMs= accessTokenExpiryMs;
    }
    //token generation
    /**
     * generates a signed jwt access token, claims included per DDR-001, sub: userId
     * role: user or admin, tokenversion: current version- checked at refresh time
     */
    public String generateAccessToken(String userId, Role role, int tokenVersion){ //creates access token
        Date now= new Date();
        Date expiry= new Date(now.getTime() + accessTokenExpiryMs);
        return Jwts.builder().id(UUID.randomUUID().toString())
                .subject(userId).claim("role", role.name())
                .claim("tokenVersion", tokenVersion).issuedAt(now)
                .expiration(expiry).signWith(signingKey).compact();
    } // id-> unique identifier for token, sub-> userId, role-> user or admin, tokenVersion-> current version, issuedAt-> when token was created, expiration-> when token expires, signWith-> signs the token with the signing key, compact()-> serializes the token

    //token validation
    /**
     * validates a jwt token- signature and expiry. returns true iff valid, false if invalid or expired.
     * never throws, all exception are caught and logged
     */
    public boolean isValid(String token){ // checks if token is valid
        try{
            parseClaims(token); // if this fails, token is invalid
            return true;
        } catch(JwtException e){
            log.debug("JWT validation failed: {}", e.getMessage());
            return false;
        } catch(Exception e){
            log.warn("Unexpected error during JWT validation: {}", e.getMessage());
            return false;
        }
    }
    //claims extraction
    /**
     * extracts the userId(subject) from a token.
     * only call this after isValid() returns true.
     */
    public String extractUserId(String token){
        return parseClaims(token).getSubject();
    }
    //extracts the role from a token & only call this after isValid() returns true
    public Role extractRole(String token){
        String roleName= parseClaims(token).get("role", String.class);
        return Role.valueOf(roleName);
    }
    /**
     * extracts the tokenVersion from a token, user at refresh time detect compromised sessions per DRR-001
     * Not checked on every request- only at refresh
     */
    public int extractTokenVersion(String token){
        return parseClaims(token).get("tokenVersion", Integer.class);
    }
    //extracts the expiry date from a token
    public Date extractExpiry(String token){
        return parseClaims(token).getExpiration();
    }
    //internal
    /**
     * parses & return all claims from a token, throws JwtException if the token is invalid or expired
     * this is the single place where token parsing happens
     */
    private Claims parseClaims(String token){
        return Jwts.parser().verifyWith(signingKey).build()
                .parseSignedClaims(token).getPayload();
    }
}
