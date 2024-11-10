//package com.vic.reservations.filter;
//
//
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
//import org.springframework.web.filter.OncePerRequestFilter;
//
//import java.io.IOException;
//
//@Component
//public class JwtFilter extends OncePerRequestFilter {
//
//    private final JwtService jwtService;
//
//    private final CustomUserDetails customUserDetails;
//
//    public JwtFilter(JwtService jwtService, CustomUserDetails customUserDetails) {
//        this.jwtService = jwtService;
//        this.customUserDetails = customUserDetails;
//    }
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//
//        String authHeader = request.getHeader("Authorization");
//
//        if(authHeader == null || !authHeader.startsWith("Bearer ")) {
//            filterChain.doFilter(request,response);
//            System.out.println("not with bearer");
//            return;
//        }
//
//        String token = authHeader.substring(7);
//        String username = jwtService.extractUsername(token);
//
//        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
//
//            UserDetails userDetails = customUserDetails.loadUserByUsername(username);
//
//
//            if(jwtService.isValid(token, userDetails)) {
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
//
//    }
//}
