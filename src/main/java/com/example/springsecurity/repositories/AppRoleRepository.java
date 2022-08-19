package com.example.springsecurity.repositories;

import com.example.springsecurity.etities.AppRole;
import com.example.springsecurity.etities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
    AppRole findByRoleName(String roleName);
}
