package com.vic.reservations.Dto;


import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {

    @NotBlank(message = "Email s required")
    private String email;

    @NotBlank(message = "Password is rquired")
    private String password;
}
