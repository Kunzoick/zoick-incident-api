package com.zoick.incidentapi.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class RefreshRequest {
    @NotBlank(message = "Refresh token is required")
    private String refreshToken;
}
