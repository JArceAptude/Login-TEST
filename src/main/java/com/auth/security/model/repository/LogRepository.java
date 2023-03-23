package com.auth.security.model.repository;

import com.auth.security.model.AdminLog;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LogRepository extends JpaRepository<AdminLog, Integer> {
}
