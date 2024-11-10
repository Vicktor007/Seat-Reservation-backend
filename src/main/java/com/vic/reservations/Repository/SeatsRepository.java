package com.vic.reservations.Repository;

import com.vic.reservations.Entity.Seats;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface SeatsRepository extends JpaRepository<Seats, Long> {

    @Query("SELECT MAX(s.id) FROM Seats s")
    Long findMaxId();
}
