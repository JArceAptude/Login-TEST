package com.auth.security.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

/***
 * This entity as a model for the database
 * Is used to log any data required by the developer.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="_admin_log")
public class AdminLog {
    @Id
    @GeneratedValue
    private Integer id;

    @Column(name = "date_action")
    private Date dateAction;

    @Column(name = "action")
    private String action;

    @Column(name = "message")
    private String message;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
}
