package com.zoick.incidentapi.dto.response;

import com.zoick.incidentapi.domain.Role;
import lombok.Builder;
import lombok.Getter;

/**
 * Response returned on successful login or refresh
 * accessToken: jwt access token-> 5min
 * refreshToken: opaque UUID-> 7 days
 * userId: for client to identify the current user
 * role: for client to render role specific UI
 */
@Getter
@Builder
public class AuthResponse {
    private String accessToken;
    private String refreshToken;
    private String userId;
    private Role role;
    private String tokenType;

    public static AuthResponse of(String accessToken, String refreshToken, String userId, Role role){
        return AuthResponse.builder().accessToken(accessToken).refreshToken(refreshToken).userId(userId)
                .role(role).tokenType("Bearer").build();
    }
}
