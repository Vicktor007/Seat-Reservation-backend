package com.vic.reservations.controller;


import com.vic.reservations.Dto.Response;
import com.vic.reservations.Service.Interfac.IUserInterface;
import com.vic.reservations.Service.OAuth2Service;
import com.vic.reservations.Service.implementation.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;

@Slf4j
@RestController
@RequestMapping("/google-auth")
public class GoogleAuthController {

    private final UserService userService;
    private final IUserInterface iUserInterface;
    private final OAuth2Service oAuth2Service;

    public GoogleAuthController(UserService userService, IUserInterface iUserInterface, OAuth2Service oAuth2Service) {
        this.userService = userService;
        this.iUserInterface = iUserInterface;
        this.oAuth2Service = oAuth2Service;
    }



    @GetMapping("/login/google")
    public ResponseEntity<String> loginGoogleAuth(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/google");
        return ResponseEntity.ok("Redirecting ..");
    }

        @GetMapping("/loginSuccess")
    public ResponseEntity<Response> handleGoogleSuccess(OAuth2AuthenticationToken oAuth2AuthenticationToken, HttpServletRequest request) {
        Response response = iUserInterface.registerOrLoginUserWithGoogle(oAuth2AuthenticationToken, request);
        System.out.println(oAuth2AuthenticationToken);

        String oauthToken = response.getAccessToken();
        System.out.println( oauthToken + " controller token");

        return ResponseEntity.status(HttpStatus.FOUND)
                .location(URI.create("http://localhost:3000/redirected?token=" + oauthToken))
                .build();
    }

    @GetMapping("/users/verify/{token}") public ResponseEntity<Response> verifyLoggedInUserWithGoogle(@PathVariable("token") String token)
    {
        Response response = oAuth2Service.verifyGoogleToken(token);
        return ResponseEntity.status(response.getStatusCode()).body(response); }
}



