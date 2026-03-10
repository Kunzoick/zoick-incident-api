package com.zoick.incidentapi.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class LoginRequest {
    @NotBlank(message = "Email is required")
    @Email(message = "Must be a valid email address")
    private String email;
    @NotBlank(message = "Password is required")
    private String password;
    @NotBlank(message = "Device ID is required")
    private String deviceId;
}
