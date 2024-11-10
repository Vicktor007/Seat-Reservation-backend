package com.vic.reservations.Repository;

import com.vic.reservations.Entity.Reservations;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ReservationRepository extends JpaRepository<Reservations, Long> {

    Optional<Reservations> findByBookingConfirmationCode(String confirmationCode);

    List<Reservations> findByUserId(UUID userId);
}
