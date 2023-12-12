package com.example.springsecuritybasic.controller.configuration;

import com.example.springsecuritybasic.model.Customer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
         http.cors((cors)->cors.disable());
         http.csrf((csrf)->csrf.disable());
     // for denying all the request ->  http.authorizeHttpRequests((request)->request.anyRequest().denyAll()).formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults());
        http.authorizeHttpRequests((request)-> request.requestMatchers("/account","myBalance","/cards","/loan").authenticated()
                .requestMatchers("/notice","/contact","/register").permitAll()).formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());

//        code to permit all the request
//        http.authorizeHttpRequests((request)->request.anyRequest().permitAll()).formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults());

        return http.build();
    }


//    @Bean
//    public InMemoryUserDetailsManager createMultipleUser(){
//
//        UserDetails admin = User.withDefaultPasswordEncoder().username("admin").password("admin").roles("admin").build();
//
//        UserDetails user = User.withDefaultPasswordEncoder().username("user").password("user").roles("user").build();
//
//        return new InMemoryUserDetailsManager(admin,user);
//    }

//    @Bean
//    public UserDetailsManager getJdbcUserDetailManager(DataSource dataSource){
//        return new JdbcUserDetailsManager(dataSource);
//    }

//    @Bean
//    public PasswordEncoder getPasswordEncoder (){
//        return NoOpPasswordEncoder.getInstance();
//    }

    @Bean
    public PasswordEncoder getPasswordEncoder(){
      return new BCryptPasswordEncoder();
    }
}
