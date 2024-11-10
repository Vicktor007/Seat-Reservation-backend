//package com.vic.reservations.utils;
//
//public class doables {
//
//    package com.vic.reservations.filter;
//
//import com.vic.reservations.Service.CustomUserDetails;
//import com.vic.reservations.Service.OAuth2Service;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
//import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
//import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
//import org.springframework.security.oauth2.core.OAuth2AccessToken;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//    @Component
//    public class JwtFilter extends OncePerRequestFilter {
//
//        private final CustomUserDetails customUserDetails;
//        private final OAuth2Service oAuth2Service;
//        private final OAuth2AuthorizedClientService authorizedClientService;
//
//        public JwtFilter(CustomUserDetails customUserDetails, OAuth2Service oAuth2Service, OAuth2AuthorizedClientService authorizedClientService) {
//            this.customUserDetails = customUserDetails;
//            this.oAuth2Service = oAuth2Service;
//            this.authorizedClientService = authorizedClientService;
//        }
//
//        @Override
//        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//            final String authHeader = request.getHeader("Authorization");
//            final String token;
//
//            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//                filterChain.doFilter(request, response);
//                return;
//            }
//
//            token = authHeader.substring(7);
//
//            // Check if the token is a JWT or an OAuth2 token
//            if (isJwtToken(token)) {
//                // Handle JWT token
//                String username = oAuth2Service.extractUsername(token);
//                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//                    UserDetails userDetails = customUserDetails.loadUserByUsername(username);
//                    if (oAuth2Service.isValid(token, userDetails)) {
//                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                                userDetails, null, userDetails.getAuthorities()
//                        );
//                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                        SecurityContextHolder.getContext().setAuthentication(authToken);
//                    }
//                }
//            } else {
//                // Handle OAuth2 token
//                OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
//                        "google", // Replace with your client registration ID
//                        SecurityContextHolder.getContext().getAuthentication().getName()
//                );
//                if (authorizedClient != null) {
//                    OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
//                    OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(
//                            authorizedClient.getPrincipal(),
//                            authorizedClient.getAuthorities(),
//                            authorizedClient.getClientRegistration().getRegistrationId()
//                    );
//                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
//                }
//            }
//            filterChain.doFilter(request, response);
//        }
//
//        private boolean isJwtToken(String token) {
//            // Implement logic to determine if the token is a JWT token
//            // For example, you can check the structure of the token or use a specific prefix
//            return token.split("\\.").length == 3;
//        }
//    }
//
//    package com.vic.reservations.filter;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//    @Component
//    public class CustomAuthFilter extends OncePerRequestFilter {
//
//        private final JwtFilter jwtFilter;
//        private final OAuth2Filter oAuth2Filter;
//
//        public CustomAuthFilter(JwtFilter jwtFilter, OAuth2Filter oAuth2Filter) {
//            this.jwtFilter = jwtFilter;
//            this.oAuth2Filter = oAuth2Filter;
//        }
//
//        @Override
//        protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//            if (authentication instanceof OAuth2AuthenticationToken) {
//                oAuth2Filter.doFilter(request, response, filterChain);
//            } else {
//                jwtFilter.doFilter(request, response, filterChain);
//            }
//        }
//    }
//
//
//}

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

//public class TokenExpiry {
//    public static void main(String[] args) {
//        // Example values
//        long expiresIn = 3544; // seconds
//        long exp = 1731059717; // Unix timestamp
//
//        // Current time in seconds since epoch
//        long currentTime = Instant.now().getEpochSecond();
//
//        // Calculate expiration time using expires_in
//        long expirationTime = currentTime + expiresIn;
//
//        // Convert expiration time to LocalDateTime
//        LocalDateTime expirationDateTime = LocalDateTime.ofInstant(Instant.ofEpochSecond(expirationTime), ZoneId.systemDefault());
//
//        // Convert exp to LocalDateTime
//        LocalDateTime expDateTime = LocalDateTime.ofInstant(Instant.ofEpochSecond(exp), ZoneId.systemDefault());
//
//        // Format the dates
//        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
//
//        System.out.println("Expiration date using expires_in: " + expirationDateTime.format(formatter));
//        System.out.println("Expiration date using exp: " + expDateTime.format(formatter));
//    }
//}

