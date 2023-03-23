package com.auth.security.model.repository;

import com.auth.security.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
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

    /**
     * Method to retrieve a user from the database, filtered by email.
     * @param isActive boolean
     * @return Optional
     */
    Optional<List<User>> findAllByIsActive(boolean isActive);
}
