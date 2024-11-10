package com.vic.reservations.Dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SeatsDto {

    private long id;

    private String seatNumber;
    private boolean reserved;
    private UserDto user;
    private ReservationsDto reservations;
}