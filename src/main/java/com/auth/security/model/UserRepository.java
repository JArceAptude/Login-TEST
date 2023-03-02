package com.auth.security.model;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * <h2>User Repository Interface</h2>
 *
 * Interface for User related Methods
 *
 * @see org.springframework.data.jpa.repository.JpaRepository
 */
public interface UserRepository extends JpaRepository<User,Integer> {
    /**
     * Method to retrieve a user from the database, filtered by email.
     * @param email String
     * @return Optional
     */
    Optional<User> findByEmail(String email);
}
