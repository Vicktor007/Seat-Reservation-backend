//package com.vic.reservations.filter;
//
//import com.vic.reservations.Service.CustomUserDetails;
//import com.vic.reservations.Service.OAuth2Service;
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
//import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@Component
//public class OAuth2Filter extends OncePerRequestFilter {
//
//    private final OAuth2Service oAuth2Service;
//    private final CustomUserDetails customUserDetails;
//
//    public OAuth2Filter(OAuth2Service oAuth2Service, CustomUserDetails customUserDetails) {
//        this.oAuth2Service = oAuth2Service;
//        this.customUserDetails = customUserDetails;
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//
//        final String authHeader = request.getHeader("Authorization");
//        final String auth2AuthenticationToken;
//        final String userEmail;
//
//        if (authHeader == null || authHeader.isBlank() ){
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        auth2AuthenticationToken = authHeader.substring(7);
//        userEmail = oAuth2Service.extractUsername(auth2AuthenticationToken);
//
//
//
//        if (auth2AuthenticationToken == null) {
//            filterChain.doFilter(request, response);
//            return;
//        }
//
//        String username = oAuth2Service.extractUsername(auth2AuthenticationToken);
//
//        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//            UserDetails userDetails = customUserDetails.loadUserByUsername(username);
//
//            if (oAuth2Service.isValid(auth2AuthenticationToken, userDetails)) {
//                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
//                        userDetails, null, userDetails.getAuthorities()
//                );
//
//                authToken.setDetails(
//                        new WebAuthenticationDetailsSource().buildDetails(request)
//                );
//
//                SecurityContextHolder.getContext().setAuthentication(authToken);
//            }
//        }
//        filterChain.doFilter(request, response);
//    }
//}
