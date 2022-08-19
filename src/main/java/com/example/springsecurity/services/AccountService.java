package com.example.springsecurity.services;

import com.example.springsecurity.etities.AppRole;
import com.example.springsecurity.etities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUserName(String username);
    List<AppUser> listUsers();
}
