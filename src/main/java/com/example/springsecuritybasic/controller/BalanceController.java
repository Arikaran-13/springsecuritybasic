package com.example.springsecuritybasic.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BalanceController{

    @GetMapping("/myBalance")
    public String getBalance(){
        return "account balance from db";
    }
}
