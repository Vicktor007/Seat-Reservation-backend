package com.vic.reservations.Service.Interfac;

import com.vic.reservations.Dto.Response;
import com.vic.reservations.Entity.Reservations;

import java.util.List;
import java.util.UUID;

public interface ReservationInterface {

    Response saveReservation(UUID userId, List<Long> seatId, Reservations reservationsRequest);

    Response findReservationByConfirmationCode(String confirmationCode);

    Response getAllReservations();

    Response cancelReservations(Long reservationId);
}
