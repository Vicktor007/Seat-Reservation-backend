package com.vic.reservations.utils;

import com.vic.reservations.Dto.ReservationsDto;
import com.vic.reservations.Dto.SeatsDto;
import com.vic.reservations.Dto.UserDto;
import com.vic.reservations.Entity.Reservations;
import com.vic.reservations.Entity.Seats;
import com.vic.reservations.Entity.User;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.stream.Collectors;

@Component
public class Utils {
    public static UserDto mapUserEntityToUserDTO(User user) {
        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setFirstName(user.getFirstName());
        userDto.setLastName(user.getLastName());
        userDto.setEmail(user.getEmail());
        userDto.setPhoneNumber(user.getPhoneNumber());
        userDto.setRole(String.valueOf(user.getRole()));
        userDto.setAuthProvider(String.valueOf(user.getAuthProvider()));
        if (user.getReservations() != null) {
            userDto.setReservations(user.getReservations().stream()
                    .map(Utils::mapReservationEntityToReservationDTO)
                    .collect(Collectors.toList()));
        }
        return userDto;
    }

    public static SeatsDto mapSeatEntityToSeatDTO(Seats seat) {
        SeatsDto seatDto = new SeatsDto();
        seatDto.setId(seat.getId());
        seatDto.setSeatNumber(seat.getSeatNumber());
        seatDto.setReserved(seat.isReserved());
        if (seat.getReservation() != null) {
            seatDto.setReservations(mapReservationEntityToReservationDTO(seat.getReservation()));
        }
        return seatDto;
    }

    public static ReservationsDto mapReservationEntityToReservationDTO(Reservations reservation) {
        ReservationsDto reservationDto = new ReservationsDto();
        reservationDto.setId(reservation.getId());
        reservationDto.setConfirmationCode(reservation.getConfirmationCode());
        if (reservation.getUser() != null) {
            reservationDto.setUser(mapUserEntityToUserDTO(reservation.getUser()));
        }
        if (reservation.getSeats() != null) {
            reservationDto.setSeats(reservation.getSeats().stream()
                    .map(Utils::mapSeatEntityToSeatDTO)
                    .collect(Collectors.toList()));
        }
        return reservationDto;
    }

    public static UserDto mapUserEntityToUserDTOPlusReservations(User user) {
        UserDto userDto = new UserDto();
        userDto.setId(user.getId());
        userDto.setFirstName(user.getFirstName());
        userDto.setEmail(user.getEmail());
        userDto.setPhoneNumber(user.getPhoneNumber());
        userDto.setRole(String.valueOf(user.getRole()));
        userDto.setAuthProvider(String.valueOf(user.getAuthProvider()));
        if (user.getReservations() != null) {
            userDto.setReservations(user.getReservations().stream()
                    .map(Utils::mapReservationEntityToReservationDTO)
                    .collect(Collectors.toList())); }
        return userDto; }

    public static ReservationsDto mapReservationEntityToReservationDTOPlusSeats(Reservations reservation, boolean mapUser) {
        ReservationsDto reservationDto = new ReservationsDto();
        reservationDto.setId(reservation.getId());
        if (mapUser) {
            reservationDto.setUser(mapUserEntityToUserDTO(reservation.getUser()));
        } if (reservation.getSeats() != null)
        { reservationDto.setSeats(reservation.getSeats().stream() .map(Utils::mapSeatEntityToSeatDTO) .collect(Collectors.toList())); }
        return reservationDto; }


    public static List<UserDto> mapUserListEntityToUserListDTO(List<User> userList) {
        return userList.stream().map(Utils::mapUserEntityToUserDTO).collect(Collectors.toList());
    }

    public static List<SeatsDto> mapSeatListEntityToSeatListDTO(List<Seats> seatList) {
        return seatList.stream().map(Utils::mapSeatEntityToSeatDTO).collect(Collectors.toList());
    }

    public static List<ReservationsDto> mapReservationListEntityToReservationListDTO(List<Reservations> reservationList) {
        return reservationList.stream().map(Utils::mapReservationEntityToReservationDTO).collect(Collectors.toList());
    }
}
