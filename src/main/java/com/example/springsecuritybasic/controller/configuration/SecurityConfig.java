package com.example.springsecuritybasic.controller.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

//      for denying all the request ->  http.authorizeHttpRequests((request)->request.anyRequest().denyAll()).formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults());
        http.authorizeHttpRequests((request)-> request.requestMatchers("/account","myBalance","/cards","/loan").authenticated()
                .requestMatchers("/notice","/contact").permitAll()).formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }
}
