package com.example.springsecuritybasic.service;

import com.example.springsecuritybasic.repository.CustomerRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;

@Service
public class CutomerUserDetails implements UserDetailsService {


    private final CustomerRepository customerRepository;

    public CutomerUserDetails(CustomerRepository customerRepository) {
        this.customerRepository = customerRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        var userDetail = customerRepository.findByEmail(username);
        if(userDetail.isEmpty()){
            throw new UsernameNotFoundException("User detail not found for the user: "+username);
        }
        var email =  userDetail.get(0).getEmail();
        var password = userDetail.get(0).getPassword();
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority(userDetail.get(0).getRole()));
        return new User(email,password,authorities);
    }
}
