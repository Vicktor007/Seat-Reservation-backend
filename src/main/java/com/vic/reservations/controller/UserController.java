package com.vic.reservations.controller;

import com.vic.reservations.Dto.Response;
import com.vic.reservations.Service.Interfac.IUserInterface;
import com.vic.reservations.Service.OAuth2Service;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    private final IUserInterface iUserInterface;

    private final OAuth2Service oAuth2Service;

    public UserController(IUserInterface iUserInterface, OAuth2Service oAuth2Service) {
        this.iUserInterface = iUserInterface;
        this.oAuth2Service = oAuth2Service;
    }

    @GetMapping("/users/all")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Response> getAlUsers() {
        Response response = iUserInterface.getAllUsers();
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("/users/get-logged-in-profile-info")
    public ResponseEntity<Response> getLoggedInUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null) {
            System.out.println("No authentication found in context");
            Response response = null;
            return ResponseEntity.status(response.getStatusCode()).body(response);
        }
        String email = authentication.getName();
        System.out.println("Authenticated user email: " + email);
        Response response = iUserInterface.getMyInfo(email);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("/get-by-id/{userId}")
    public ResponseEntity<Response> getUserById(@PathVariable("userId") String userId) {
        Response response = iUserInterface.getUserById(userId);
        return  ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @DeleteMapping("/delete/{userId}")
    @PreAuthorize("hasAuthority('ADMIN') or hasAuthority('USER')")
    public ResponseEntity<Response> deleteUser(@PathVariable("userId") String userId) {
        Response response = iUserInterface.deleteUser(userId);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }


    @GetMapping("/get-user-reservations/{userId}")
    public ResponseEntity<Response> getUserReservations(@PathVariable("userId") String userId){
        Response response = iUserInterface.getUserReservations(userId);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

}

