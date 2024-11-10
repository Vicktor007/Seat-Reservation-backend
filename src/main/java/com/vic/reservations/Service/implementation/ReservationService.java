package com.vic.reservations.Service.implementation;

import com.vic.reservations.Dto.ReservationsDto;
import com.vic.reservations.Dto.Response;
import com.vic.reservations.Entity.Reservations;
import com.vic.reservations.Entity.Seats;
import com.vic.reservations.Entity.User;
import com.vic.reservations.Repository.ReservationRepository;
import com.vic.reservations.Repository.SeatsRepository;
import com.vic.reservations.Repository.UserRepository;
import com.vic.reservations.Service.Interfac.ReservationInterface;
import com.vic.reservations.exception.MyException;
import com.vic.reservations.utils.Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class ReservationService implements ReservationInterface {

    @Autowired
    private ReservationRepository reservationRepository;

    @Autowired
    private SeatsRepository seatsRepository;

    @Autowired
    private UserRepository userRepository;

    @Override
    public Response saveReservation(UUID userId, List<Long> seatIds, Reservations reservationsRequest) {
        Response response = new Response();
        try {
            Optional<User> userOptional = userRepository.findById(userId);
            if (!userOptional.isPresent()) {
                response.setStatusCode(404);
                response.setMessage("User not found");
                return response;
            }

            User user = userOptional.get();
            Reservations reservation = new Reservations();
            reservation.setUser(user);
             reservation.setConfirmationCode(UUID.randomUUID().toString());
            String confirmationCode = reservation.getConfirmationCode();
            for (Long seatId : seatIds) {
                Optional<Seats> seatOptional = seatsRepository.findById(seatId);
                if (!seatOptional.isPresent()) {
                    response.setStatusCode(404);
                    response.setMessage("Seat with ID " + seatId + " not found");
                    return response;
                }

                Seats seat = seatOptional.get();
                if (seat.isReserved()) {
                    response.setStatusCode(400);
                    response.setMessage("Seat with ID " + seatId + " is already reserved");
                    return response;
                }

                seat.setReserved(true);
                seat.setReservation(reservation);
                reservation.getSeats().add(seat);
            }

           Reservations savedReservations =  reservationRepository.save(reservation);
            ReservationsDto reservationsDto = Utils.mapReservationEntityToReservationDTO(savedReservations);
            response.setStatusCode(200);
            response.setMessage("Reservation created successfully");
            reservation.setConfirmationCode(confirmationCode);
            response.setReservationsList((List<ReservationsDto>) reservationsDto);
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error creating reservation: " + e.getMessage());
        }
        return response;
    }

    @Override
    public Response findReservationByConfirmationCode(String confirmationCode) {
       Response response = new Response();
       try {
           Reservations reservations = reservationRepository.findByBookingConfirmationCode(confirmationCode).orElseThrow(() -> new MyException("Reservation not found"));
           ReservationsDto reservationsDto = Utils.mapReservationEntityToReservationDTOPlusSeats(reservations, true);
           response.setStatusCode(200);
           response.setReservationsDto(reservationsDto);
       } catch (MyException e) {
           response.setStatusCode(404);
           response.setMessage(e.getMessage());
       } catch (Exception e)
       {
           response.setStatusCode(500);
           response.setMessage("Error finding a reservation: " + e.getMessage());
       }
       return response;
    }

    @Override
    public Response getAllReservations() {
        Response response = new Response();
        try {
            List<Reservations> reservationsList = reservationRepository.findAll(Sort.by(Sort.Direction.DESC,"id"));
            List<ReservationsDto> reservationsDtoList = Utils.mapReservationListEntityToReservationListDTO(reservationsList);
            response.setStatusCode(200);
            response.setMessage("Successful");
            response.setReservationsList(reservationsDtoList);
        } catch (MyException e) {
            response. setStatusCode(404);
            response.setMessage(e.getMessage());
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error getting all reservations: " + e.getMessage());
        }
        return response;
    }

    @Override
    public Response cancelReservations(Long reservationId) {
        Response response = new Response();
        try {
            Reservations reservations = reservationRepository.findById(reservationId).orElseThrow(() -> new MyException("Reservation does not exist"));
            reservationRepository.deleteById(reservationId);
            response.setStatusCode(200);
            response.setMessage("successful");
        } catch (MyException e) {
            response.setStatusCode(404);
            response.setMessage(e.getMessage());

        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error Cancelling a reservation: " + e.getMessage());

        }
        return response;
    }
}
