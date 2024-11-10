package com.vic.reservations.Service.Interfac;

import com.vic.reservations.Dto.Response;

public interface ISeatsInterface {
    Response createSeats(int numberOfSeats);
    Response getAllSeats();
    Response addSeats(int numberOfSeats);
    Response removeSeats(int numberOfSeats);
    Response deleteAllSeats();
}
