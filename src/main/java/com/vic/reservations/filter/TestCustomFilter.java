//package com.vic.reservations.filter;
//
//
//import com.vic.reservations.Repository.UserRepository;
//import com.vic.reservations.Service.CustomUserDetails;
//import com.vic.reservations.Service.JwtService;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.client.RestTemplate;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@Component
//public class CustomFilter extends OncePerRequestFilter {
//
//    private final JwtService jwtService;
//
//    private final CustomUserDetails customUserDetails;
//
//    private final UserRepository userRepository;
//
//    public CustomFilter(JwtService jwtService, CustomUserDetails customUserDetails, UserRepository userRepository) {
//        this.jwtService = jwtService;
//        this.customUserDetails = customUserDetails;
//        this.userRepository = userRepository;
//    }
//
//    public static class GoogleTokenInfo {
//        private String email;
//
//        // Getters and setters
//        public String getEmail() {
//            return email;
//        }
//
//        public void setEmail(String email) {
//            this.email = email;
//        }
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
////        String authHeader = request.getHeader("Authorization");
////
////        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
////            filterChain.doFilter(request,response);
////            System.out.println("not with bearer");
////            return;
////        }
//
//        String authHeader = request.getHeader("Authorization");
//        String AuthProvider = request.getHeader("AuthProvider");
//
//        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
//            filterChain.doFilter(request, response);
//            System.out.println("custom filter not with bearer");
//            return;
//        }
//
//        String token = authHeader.substring(7);
//
//        if ( AuthProvider != null && AuthProvider.equals("Google")) {
//
//            String url = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + token;
//            RestTemplate restTemplate = new RestTemplate();
//            GoogleTokenInfo tokenInfo = restTemplate.getForObject(url, GoogleTokenInfo.class);
//
//            if (tokenInfo != null && tokenInfo.getEmail() != null) {
//                String Email = tokenInfo.getEmail();
//                var user = userRepository.findByEmail(Email).orElse(null);
//                if (user != null) {
//
//                    String accessToken = token;
//                    System.out.println(accessToken);
//
//                    if (Email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//
//                        UserDetails userDetails = customUserDetails.loadUserByUsername(Email);
//
//
//                        if (userDetails != null) {
//                            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                                    userDetails, null, ((UserDetails) userDetails).getAuthorities()
//                            );
//
//                            authToken.setDetails(
//                                    new WebAuthenticationDetailsSource().buildDetails(request)
//                            );
//
//                            SecurityContextHolder.getContext().setAuthentication(authToken);
//                        }
//                    }
//                } else {
//
//
//
//                    String username = jwtService.extractUsername(token);
//
//                    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//
//                        UserDetails userDetails = customUserDetails.loadUserByUsername(username);
//
//
//                        if (jwtService.isValid(token, userDetails)) {
//                            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                                    userDetails, null, ((UserDetails) userDetails).getAuthorities()
//                            );
//
//                            authToken.setDetails(
//                                    new WebAuthenticationDetailsSource().buildDetails(request)
//                            );
//
//                            SecurityContextHolder.getContext().setAuthentication(authToken);
//                        }
//                    }}
//                filterChain.doFilter(request, response);
//
//            }
//
//
//        }
//    }}