package com.example.springsecuritybasic.configuration;

import com.example.springsecuritybasic.model.Customer;
import jakarta.servlet.http.HttpServletRequest;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.sql.DataSource;
import java.util.Collections;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.cors().configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration config = new CorsConfiguration();
                config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                config.setAllowedMethods(Collections.singletonList("*"));
                config.setAllowCredentials(true);
                config.setAllowedHeaders(Collections.singletonList("*"));
                config.setMaxAge(3600L);
                return config;
            }
        });
         http.csrf((csrf)->csrf.disable());
     // for denying all the request ->  http.authorizeHttpRequests((request)->request.anyRequest().denyAll()).formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults());
        http.authorizeHttpRequests((request)-> request.requestMatchers("/account","myBalance","/cards","/loan","/user").authenticated()
                .requestMatchers("/notices","/contact","/register").permitAll()).formLogin(Customizer.withDefaults())
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
