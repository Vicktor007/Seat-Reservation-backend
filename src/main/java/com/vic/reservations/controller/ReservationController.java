package com.vic.reservations.controller;

import com.vic.reservations.Dto.Response;
import com.vic.reservations.Entity.Reservations;
import com.vic.reservations.Service.Interfac.ReservationInterface;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api")
public class ReservationController {

    @Autowired
    ReservationInterface reservationInterface;

    @PostMapping("/makeReservations")
    @PreAuthorize("hasAuthority('ADMIN') or hasAuthority('USER')")
    public ResponseEntity<Response> createReservation(@RequestParam UUID userId, @RequestParam List<Long> seatIds, @RequestBody Reservations reservationsRequest) {
        Response response = reservationInterface.saveReservation(userId,seatIds,reservationsRequest);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("/all-reservations")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Response> getAllReservations() {
        Response response = reservationInterface.getAllReservations();
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @GetMapping("get-by-confirmationCode/{confirmationCode}")
    public ResponseEntity<Response> getReservationByConfirmationCode(@PathVariable String confirmationCode) {
        Response response = reservationInterface.findReservationByConfirmationCode(confirmationCode);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }

    @DeleteMapping("/cancel-reservation/{reservationId}")
    @PreAuthorize("hasAuthority('ADMIN') or hasAuthority('USER')")
    public ResponseEntity<Response> cancelReservation(@PathVariable Long reservationId) {
        Response response = reservationInterface.cancelReservations(reservationId);
        return ResponseEntity.status(response.getStatusCode()).body(response);
    }
}
