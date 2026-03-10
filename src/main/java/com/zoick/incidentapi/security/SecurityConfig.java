package com.zoick.incidentapi.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.core.Ordered;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * central security configuration class-> it defines
 * which endpoints are protected vs public
 * role based access per endpoint
 * jwt filter placement in the filter chain
 * password encoder(bcrypt)
 * this role(iron rule) -> role governs structural access to endpoints
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtFilter jwtFilter;
    private final UserDetailsServiceImpl userDetailsService;
    private final RateLimitFilter rateLimitFilter;
    /**
     * Defines the security filter chain.
     *
     * Authorization rules per endpoint map from blueprint:
     * - /api/v1/auth/** — public (register, login, refresh)
     * - /actuator/health — public (monitoring)
     * - /api/v1/admin/** — ADMIN role only
     * - /api/v1/** — authenticated users (USER or ADMIN)
     * - everything else — denied
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http)// defines who can access what.
            throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable) // crsf(is used for session based apps)protection is not needed for stateless api
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // stateless(api doesn't use sessions)
                )
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints — no token required
                        .requestMatchers(
                                "/api/v1/auth/register",
                                "/api/v1/auth/login",
                                "/api/v1/auth/refresh"
                        ).permitAll()

                        // Actuator health — public for monitoring
                        .requestMatchers("/actuator/health").permitAll()

                        // Admin endpoints — ADMIN role required
                        .requestMatchers("/api/v1/admin/**")
                        .hasRole("ADMIN")

                        // All other API endpoints — authenticated only
                        .requestMatchers("/api/v1/**")
                        .authenticated()

                        // Everything else — deny
                        .anyRequest().denyAll()
                )
                .authenticationProvider(authenticationProvider())// uses our authentication provider
                .addFilterBefore(jwtFilter,
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterAfter(rateLimitFilter, JwtFilter.class);

        return http.build();
    }
    /**
     * Authentication provider- wires our UserDetailsService
     * and password encorder together for spring security.
     */
    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider provider= new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }
    //AuthenticationManager- used by authService to authenticate users
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
    /**
     * Bcrypt password encorder-> strength 12-> strong enough for protection, acceptable performance for development
     * this is the only place bcrypt strength is defined
     */
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(12);
    }
    @Bean
    public FilterRegistrationBean<CorrelationFilter> correlationFilterFilterRegistration(){
        FilterRegistrationBean<CorrelationFilter> registration= new FilterRegistrationBean<>();
        registration.setFilter(new CorrelationFilter());
        registration.addUrlPatterns("/*");
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registration;
    }
}
