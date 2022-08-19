package com.example.springsecurity.services;

import com.example.springsecurity.etities.AppUser;
import lombok.AllArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
@Service
@AllArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private AccountService accountService;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AppUser appUser =accountService.loadUserByUserName(username);
        Collection<GrantedAuthority> authorities=new ArrayList<>();
        appUser.getRoles().forEach(appRole -> {
            authorities.add(new SimpleGrantedAuthority(appRole.getRoleName()));
        });
        return new User(appUser.getUsername(),appUser.getPassword(),authorities);//spring user
    }
}
