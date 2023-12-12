package com.example.springsecuritybasic.repository;

import com.example.springsecuritybasic.model.Customer;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface CustomerRepository extends JpaRepository<Customer,Integer> {

    List<Customer>findByEmail(String email);
}
