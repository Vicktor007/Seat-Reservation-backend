package com.vic.reservations.controller;

import com.vic.reservations.Dto.LoginRequest;
import com.vic.reservations.Dto.Response;
import com.vic.reservations.Entity.User;
import com.vic.reservations.Service.Interfac.IUserInterface;
import com.vic.reservations.Service.implementation.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final IUserInterface iUserInterface;

    public AuthController(UserService userService, IUserInterface iUserInterface) {
        this.userService = userService;
        this.iUserInterface = iUserInterface;
    }

    @PostMapping("/register")
    public ResponseEntity<Response> localRegistration(@RequestBody @Validated User user) {
        Response response = iUserInterface.registerUserLocally(user);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/sign-in/local")
    public ResponseEntity<Response> localLogin(@RequestBody LoginRequest loginRequest) {
        Response response = iUserInterface.loginUserLocally(loginRequest);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

//    @GetMapping("/verify")
//    public ResponseEntity<Response> verifyLoggedInUserWithGoogle(@RequestBody OAuth2AuthenticationToken oAuth2AuthenticationToken) {
//        Response response = iUserInterface.verifyLoggedInUserWithGoogle(oAuth2AuthenticationToken);
//        return ResponseEntity.status(response.getStatusCode()).body(response);
//    }


}
