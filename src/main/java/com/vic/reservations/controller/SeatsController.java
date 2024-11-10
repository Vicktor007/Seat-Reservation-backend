package com.vic.reservations.controller;

import com.vic.reservations.Dto.Response;
import com.vic.reservations.Service.Interfac.ISeatsInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class SeatsController {

    @Autowired
    private ISeatsInterface iSeatsInterface;

    @PostMapping("/seats/create")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Response> createSeats(@RequestParam int numberOfSeats) {
         Response response =iSeatsInterface.createSeats(numberOfSeats);
         return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("/seats/all")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Response> getAllSeats() {
        Response response = iSeatsInterface.getAllSeats();
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @PostMapping("/seats/add")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Response> addSeats(@RequestParam int numberOfSeats) {
        Response response = iSeatsInterface.addSeats(numberOfSeats);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @DeleteMapping("/seats/remove")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Response> removeSeats(@RequestParam int numberOfSeats) {
        Response response = iSeatsInterface.removeSeats(numberOfSeats);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @DeleteMapping("/seats/delete-all")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Response> deleteAllSeats() {
        Response response = iSeatsInterface.deleteAllSeats();
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }
}
