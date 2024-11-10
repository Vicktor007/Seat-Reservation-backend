package com.vic.reservations.Service.implementation;

import com.vic.reservations.Dto.Response;
import com.vic.reservations.Dto.SeatsDto;
import com.vic.reservations.Entity.Seats;
import com.vic.reservations.Repository.SeatsRepository;
import com.vic.reservations.Service.Interfac.ISeatsInterface;
import com.vic.reservations.utils.Utils;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class SeatService implements ISeatsInterface {

    @Autowired
    private SeatsRepository seatsRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Override
    public Response createSeats(int numberOfSeats) {
        Response response = new Response();
        try {
            // Create new seats
            for (int i = 0; i < numberOfSeats; i++) {
                Seats seat = new Seats();
                seat.setReserved(false);
                seatsRepository.save(seat);
            }
            response.setStatusCode(200);
            response.setMessage("Successfully created " + numberOfSeats + " seats.");
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error creating seats: " + e.getMessage());
            // Log the exception for debugging purposes
            e.printStackTrace();
        }
        return response;
    }

    @Override
    public Response getAllSeats() {
        Response response = new Response();
        try {
            List<Seats> seatsList =
                    seatsRepository.findAll(Sort.by(Sort.Direction.DESC, "id" ));
            List < SeatsDto> seatsDtoList = Utils.mapSeatListEntityToSeatListDTO(seatsList);
            response.setStatusCode(200);
            response.setMessage("Successful");
            response.setSeatsList(seatsDtoList);
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error getting all seats" + e.getMessage());
        }
        return response;
    }

    @Override
    @Transactional
    public Response addSeats(int numberOfSeats) {
        Response response = new Response();
        try {
            // Find the highest existing ID
            Long maxId = seatsRepository.findMaxId();
            if (maxId == null) {
                maxId = 0L;
            }

            // Adjust the sequence value
            entityManager.createNativeQuery("ALTER SEQUENCE seats_id_seq RESTART WITH " + (maxId + 1)).executeUpdate();

            // Create new seats
            for (int i = 0; i < numberOfSeats; i++) {
                Seats seat = new Seats();
                seat.setReserved(false);
                seatsRepository.save(seat);
            }
            response.setStatusCode(200);
            response.setMessage("Successfully added " + numberOfSeats + " seats.");
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error adding seats: " + e.getMessage());
            // Log the exception for debugging purposes
            e.printStackTrace();
        }
        return response;
    }

    @Override
    public Response removeSeats(int numberOfSeats) {
        Response response = new Response();
        try {
            List<Seats> seats = seatsRepository.findAll();
            if (seats.size() < numberOfSeats) {
                response.setStatusCode(400);
                response.setMessage("Not enough seats to remove.");
                return response;
            }
            for (int i = 0; i < numberOfSeats; i++) {
                seatsRepository.delete(seats.get(seats.size() - 1 - i));
            }
            response.setStatusCode(200);
            response.setMessage("Successfully removed " + numberOfSeats + " seats.");
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error removing seats: " + e.getMessage());
        }
        return response;
    }

    @Override
    @Transactional
    public Response deleteAllSeats() {
        Response response = new Response();
        try {
            seatsRepository.deleteAll();
            entityManager.flush(); // Ensure all deletions are flushed to the database
            entityManager.createNativeQuery("ALTER SEQUENCE seats_id_seq RESTART WITH 1").executeUpdate();
            response.setStatusCode(200);
            response.setMessage("Successfully deleted all seats and reset ID sequence.");
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error deleting all seats: " + e.getMessage());
            // Log the exception for debugging purposes
            e.printStackTrace();
        }
        return response;
    }
}

