//package com.vic.reservations.Config;
//
//import com.vic.reservations.Service.CustomUserDetails;
//import com.vic.reservations.filter.JwtFilter;
//import jakarta.servlet.http.HttpServletResponse;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.http.HttpStatus;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.config.Customizer;
//import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
//import org.springframework.security.config.http.SessionCreationPolicy;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.authentication.HttpStatusEntryPoint;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//@Slf4j
//@Configuration
//@EnableWebSecurity
//public class SecurityConfig {
//
//    private final CustomUserDetails customUserDetails;
//    private final JwtFilter jwtFilter;
//    private final CustomLogoutHandler logoutHandler;
//
//    public SecurityConfig(CustomUserDetails customUserDetails, JwtFilter jwtFilter, CustomLogoutHandler logoutHandler) {
//        this.customUserDetails = customUserDetails;
//        this.jwtFilter = jwtFilter;
//        this.logoutHandler = logoutHandler;
//    }
//
//    @Order(1)
//    @Bean
//    public SecurityFilterChain signInSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
//        return httpSecurity
//                .cors(Customizer.withDefaults())
//                .csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(auth -> auth
//                        .requestMatchers("/auth/sign-in/**")
//                        .permitAll()
//                        .anyRequest().authenticated())
//                .userDetailsService(customUserDetails)
//
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .exceptionHandling(ex -> {
//                    ex.authenticationEntryPoint((request, response, authException) ->
//                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
//                })
//                .httpBasic(Customizer.withDefaults())
//                .build();
//    }
//
//    @Order(2)
//    @Bean
//
//    public SecurityFilterChain googleSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity
//                .csrf(AbstractHttpConfigurer::disable)
//                .cors(Customizer.withDefaults())
//                .authorizeHttpRequests(requests -> requests
//                        .requestMatchers("/google-auth/**").permitAll()
//                        .anyRequest().authenticated())
//                .oauth2Login(oauth2 -> oauth2
//                        .loginPage("/google-auth/login/google")
//                        .defaultSuccessUrl("/google-auth/loginSuccess", true)
//                        .failureUrl("/loginFailure"));
//
//        return httpSecurity.build();
//    }
//
////    public SecurityFilterChain googleLoginFilterChain(HttpSecurity httpSecurity) throws Exception {
////       return httpSecurity
////                .cors(Customizer.withDefaults())
////                .securityMatcher(new AntPathRequestMatcher("/google-auth/**"))
////                .csrf(AbstractHttpConfigurer::disable)
////                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
////                .oauth2Login(oauth2 -> oauth2
////                        .loginPage("/google-auth/login/google")
////                        .defaultSuccessUrl("/google-auth/loginSuccess", true)
////                        .failureUrl("/loginFailure"))
////                .exceptionHandling(ex -> {
////                    ex.authenticationEntryPoint((request, response, authException) ->
////                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
////                })
////                .httpBasic(Customizer.withDefaults())
////                .build();
////
////    }
//
//
////    @Order(3)
////    @Bean
////    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
////        return httpSecurity
////                .csrf(AbstractHttpConfigurer::disable)
////                .authorizeHttpRequests(auth -> auth
////                      .requestMatchers("/api/**")
////                        .permitAll()
////                        .anyRequest().authenticated())
////                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
////                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
////                .exceptionHandling(ex -> {
////                    log.error("[SecurityConfig:apiSecurityFilterChain] Exception due to :{}",ex);
////                    ex.authenticationEntryPoint((request, response, authException) ->
////                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
////                })
////                .httpBasic(Customizer.withDefaults())
////                .build();
////    }
//
//    @Order(4)
//    @Bean
//    public SecurityFilterChain logoutSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        return httpSecurity
//                .securityMatcher(new AntPathRequestMatcher("/logout/**"))
//                .csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
//                .logout(logout -> logout
//                        .logoutUrl("/logout")
//                        .addLogoutHandler(logoutHandler)
//                        .logoutSuccessHandler(((request, response, authentication) -> SecurityContextHolder.clearContext()))
//                )
//                .exceptionHandling(ex -> {
//                    log.error("[SecurityConfig:logoutSecurityFilterChain] Exception due to :{}",ex);
//
//                        ex.authenticationEntryPoint((request, response, authException) ->
//                                response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
//                    })
//                .build();
//    }
//
//    @Order(5)
//    @Bean
//    public SecurityFilterChain registerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
//        return httpSecurity
//                .securityMatcher(new AntPathRequestMatcher("/auth/register/**"))
//                .csrf(AbstractHttpConfigurer::disable)
//                .authorizeHttpRequests(auth ->
//                        auth.anyRequest().permitAll())
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
//                .exceptionHandling(ex -> {
//                    ex.authenticationEntryPoint((request, response, authException) ->
//                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
//                })
//                .build();
//    }
//
//
//
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
//    @Bean
//    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
//        return configuration.getAuthenticationManager();
//    }
//}


package com.vic.reservations.Config;

import com.vic.reservations.Service.CustomUserDetails;
import com.vic.reservations.filter.CustomFilter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CustomUserDetails customUserDetails;

    private final CustomLogoutHandler logoutHandler;
    private final CustomFilter customFilter;

    public SecurityConfig(CustomUserDetails customUserDetails, CustomLogoutHandler logoutHandler, CustomFilter customFilter) {
        this.customUserDetails = customUserDetails;


        this.logoutHandler = logoutHandler;
        this.customFilter = customFilter;
    }

    @Order(1)
    @Bean
    public SecurityFilterChain registerSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/auth/register/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth ->
                        auth.anyRequest().permitAll())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint((request, response, authException) ->
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
                })
                .build();
    }

    @Order(2)
    @Bean
    public SecurityFilterChain signInSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{

        return httpSecurity
                .securityMatcher(new AntPathRequestMatcher("/auth/sign-in/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .userDetailsService(customUserDetails)

                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint((request, response, authException) ->
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
                })
                .httpBasic(Customizer.withDefaults())
                .build();
    }

    @Order(3)
    @Bean
    public SecurityFilterChain apiSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher(new AntPathRequestMatcher("/api/**"))
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(
                                 req->req
                                .anyRequest()
                                .authenticated()
                )
                .sessionManagement(session->session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(
                        e->e.accessDeniedHandler(
                                        (request, response, accessDeniedException)->response.setStatus(403)
                                )
                                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))

                .build();
    }

    @Order(4)
    @Bean
    public SecurityFilterChain googleSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .cors(Customizer.withDefaults())
                .authorizeHttpRequests(requests -> requests
                        .requestMatchers("/google-auth/**").permitAll()
                        .anyRequest().authenticated())

                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/google-auth/login/google")
                        .defaultSuccessUrl("/google-auth/loginSuccess", true)
                        .failureUrl("/loginFailure"))
                .exceptionHandling(ex -> {
                    ex.authenticationEntryPoint((request, response, authException) ->
                            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage()));
                })
                ;

        return httpSecurity.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}

