package com.vic.reservations.Entity;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "seats")
public class Seats {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long id;

    private String seatNumber;

    @Column(columnDefinition = "boolean default false")
    private boolean reserved = false;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "reservation_id")
    private Reservations reservation;

    @PostPersist
    public void prePersist() {
        this.seatNumber = String.valueOf(this.id);
    }
}
