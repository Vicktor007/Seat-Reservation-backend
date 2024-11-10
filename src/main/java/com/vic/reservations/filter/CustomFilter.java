package com.vic.reservations.filter;

import com.vic.reservations.Repository.UserRepository;
import com.vic.reservations.Service.CustomUserDetails;
import com.vic.reservations.Service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class CustomFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetails customUserDetails;
    private final UserRepository userRepository;

    public CustomFilter(JwtService jwtService, CustomUserDetails customUserDetails, UserRepository userRepository) {
        this.jwtService = jwtService;
        this.customUserDetails = customUserDetails;
        this.userRepository = userRepository;
    }

    public static class GoogleTokenInfo {
        private String email;

        // Getters and setters
        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");
        System.out.println(authHeader);
        String authProvider = request.getHeader("AuthProvider");
        System.out.println(authHeader);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            System.out.println("custom filter not with bearer");
            return;
        }

        String token = authHeader.substring(7);

        if (authProvider != null && authProvider.equals("GOOGLE")) {
            String url = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + token;
            RestTemplate restTemplate = new RestTemplate();
            GoogleTokenInfo tokenInfo = restTemplate.getForObject(url, GoogleTokenInfo.class);

            if (tokenInfo != null && tokenInfo.getEmail() != null) {
                String email = tokenInfo.getEmail();
                var user = userRepository.findByEmail(email).orElse(null);
                if (user != null) {
                    if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                        UserDetails userDetails = customUserDetails.loadUserByUsername(email);
                        if (userDetails != null) {
                            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                    userDetails, null, userDetails.getAuthorities()
                            );
                            authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                            SecurityContextHolder.getContext().setAuthentication(authToken);
                            System.out.println("Google authentication set for user: " + email);
                        }
                    }
                }
            }
        } else {
            String username = jwtService.extractUsername(token);
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = customUserDetails.loadUserByUsername(username);
                if (jwtService.isValid(token, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    System.out.println("JWT authentication set for user: " + username);
                }
            }
        }
        filterChain.doFilter(request, response);
    }
}
