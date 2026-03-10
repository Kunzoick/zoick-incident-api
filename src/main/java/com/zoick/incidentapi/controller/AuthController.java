package com.zoick.incidentapi.controller;

import com.zoick.incidentapi.dto.request.LoginRequest;
import com.zoick.incidentapi.dto.request.RefreshRequest;
import com.zoick.incidentapi.dto.request.RegisterRequest;
import com.zoick.incidentapi.dto.response.AuthResponse;
import com.zoick.incidentapi.service.AuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

/**
 * Authentication controller- http layer only
 * receives requests, validates input shape via "valid, delegates entirely to authService, returns responses
 * Zero business logic here and security logic here, this class isnt about http, but it belongs in authService
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    //register a new user, returns 201 crreated with no body on success, email uniqueness violation returns 409
    @PostMapping("/register")
    public ResponseEntity<Void> register(@Valid @RequestBody RegisterRequest request, HttpServletRequest httpRequest){
        authService.register(request.getEmail(), request.getPassword(), httpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }
    /**
     * login with email and password
     * returns jwt access token + refresh token on success
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest){
        AuthService.LoginResult result= authService.login(request.getEmail(), request.getPassword(), request.getDeviceId(),httpRequest);
        return ResponseEntity.ok(AuthResponse.of(result.accessToken(), result.refreshTokenId(), result.userId(), result.role()));
    }
    //refresh jwt access token with refresh token, old refresh token is invalidated
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request, HttpServletRequest httpRequest){
        AuthService.LoginResult result= authService.refresh(request.getRefreshToken(), httpRequest);
        return ResponseEntity.ok(AuthResponse.of(result.accessToken(), result.refreshTokenId(), result.userId(), result.role()));
    }
    /**
     * Logout — revokes the refresh token.
     * Access token expires naturally within 5 minutes.
     * Returns 204 No Content.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @Valid @RequestBody RefreshRequest request,
            @AuthenticationPrincipal UserDetails userDetails,
            HttpServletRequest httpRequest
    ) {
        authService.logout(
                request.getRefreshToken(),
                userDetails.getUsername(),
                httpRequest
        );
        return ResponseEntity.noContent().build();
    }
}
