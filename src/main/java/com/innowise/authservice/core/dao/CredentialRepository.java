package com.innowise.authservice.core.dao;

import com.innowise.authservice.core.entity.Credential;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CredentialRepository extends JpaRepository<Credential, Long> {

    Optional<Credential> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<Credential> findBySub(UUID sub);
}
