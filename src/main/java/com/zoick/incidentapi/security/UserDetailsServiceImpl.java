package com.zoick.incidentapi.security;

import com.zoick.incidentapi.domain.User;
import com.zoick.incidentapi.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Bridges our User domain object to Spring Security.
 *
 * loadUserByUsername is called in two contexts:
 * 1. Login — called with email by AuthService
 * 2. JWT Filter — called with userId by JwtFilter
 *
 * We handle both by trying userId first, then email.
 * This keeps Spring Security's contract intact while
 * supporting both authentication flows.
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Loads a user by userId or email.
     *
     * JwtFilter passes userId (UUID format).
     * AuthService passes email during login.
     *
     * We detect which one by checking if the input
     * looks like a UUID — if yes, find by ID,
     * otherwise find by email.
     */
    @Override
    public UserDetails loadUserByUsername(String identifier)
            throws UsernameNotFoundException {

        User user = isUUID(identifier)
                ? userRepository.findById(identifier)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found by id: " + identifier))
                : userRepository.findByEmail(identifier)
                .orElseThrow(() -> new UsernameNotFoundException(
                        "User not found by email: " + identifier));

        return org.springframework.security.core.userdetails.User
                .withUsername(user.getId())
                .password(user.getPasswordHash())
                .authorities(List.of(
                        new SimpleGrantedAuthority(
                                "ROLE_" + user.getRole().name())
                ))
                .accountLocked(user.isAccountLocked())
                .build();
    }

    /**
     * Detects if the identifier is a UUID (from JWT filter)
     * or an email (from login flow).
     */
    private boolean isUUID(String value) {
        try {
            java.util.UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}