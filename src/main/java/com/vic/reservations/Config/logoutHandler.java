package com.vic.reservations.Config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class logoutHandler implements LogoutHandler {

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            revokeGoogleToken(token);
        }
    }

    private void revokeGoogleToken(String token) {
        String url = "https://accounts.google.com/o/oauth2/revoke?token=" + token;
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.postForObject(url, null, String.class);
    }
}
