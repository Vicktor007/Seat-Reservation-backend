package com.vic.reservations.Dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;


@Data
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public class Response {

        private int statusCode;

        @JsonProperty("message")
        private String message;

        @JsonProperty("access_token")
        private String accessToken;

        @JsonProperty("refresh_token")
        private String refreshToken;

        private String role;
        private String expirationTime;
        private String confirmationCode;
        private String authProvider;

        private UserDto user;
        private SeatsDto seats;
        private ReservationsDto reservationsDto;
        private List<UserDto> userList;
        private List<SeatsDto> seatsList;
        private List<ReservationsDto> reservationsList;

    }

