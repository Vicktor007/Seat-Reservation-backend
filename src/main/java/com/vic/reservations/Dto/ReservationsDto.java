package com.vic.reservations.Dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ReservationsDto {

    private Long id;

    private String confirmationCode;

    private UserDto user;

    private List<SeatsDto> seats = new ArrayList<>();
}
