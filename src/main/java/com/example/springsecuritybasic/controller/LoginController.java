package com.example.springsecuritybasic.controller;

import com.example.springsecuritybasic.model.Customer;
import com.example.springsecuritybasic.repository.CustomerRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
@RestController
public class LoginController{

    private final CustomerRepository customerRepository;

    private final PasswordEncoder encoder;

    public LoginController(CustomerRepository customerRepository, PasswordEncoder encoder) {
        this.customerRepository = customerRepository;
        this.encoder = encoder;
    }

    @PostMapping("/register")
    public ResponseEntity<String>registerUser(@RequestBody Customer customer){
        ResponseEntity<String> response;
       var hashedPwd = encoder.encode(customer.getPassword());
       customer.setPassword(hashedPwd);
       try {
           customerRepository.save(customer);
           response = ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
       }catch (Exception e){

           response = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An exception occurred due to "+e.getMessage());
       }
       return response;
    }
}