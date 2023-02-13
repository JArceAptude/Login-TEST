package com.auth.security.model;

import org.springframework.data.jpa.repository.JpaRepository;

public interface LogRepository extends JpaRepository<AdminLog, Integer> {
}
