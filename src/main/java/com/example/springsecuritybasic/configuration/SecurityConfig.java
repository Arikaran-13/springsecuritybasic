package com.example.springsecuritybasic.configuration;

import com.example.springsecuritybasic.filter.CsrfCookieFilter;
import com.example.springsecuritybasic.filter.JwtGenerationFilter;
import com.example.springsecuritybasic.filter.JwtValidatorFilter;
import com.example.springsecuritybasic.filter.RequestValidateFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;

import java.util.Collections;
import java.util.List;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        var handler = new CsrfTokenRequestAttributeHandler();
        handler.setCsrfRequestAttributeName("_csrf");
//        http.securityContext(securityContext -> securityContext.requireExplicitSave(false)) // when using jsession id we want this config to inform spring that create session always
//                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // but while using jwt tokens we don't need session so we can say it as stateless
                .cors(cors -> cors.configurationSource(request -> {
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    config.setAllowedMethods(Collections.singletonList("*"));
                    config.setAllowCredentials(true);
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    // we also need to send back the jwt token to UI application that deployed in diff origin( localhost:4400) so we need to inform cors that i am going to pass response header called authentication (where inside this we will gill JWT token)
                    config.setExposedHeaders(List.of("Authentication")); // for sending response as jwt token to UI we need to give permission to avoid cors error
                    config.setMaxAge(3600L);
                    return config;
                })).csrf(csrf -> csrf.csrfTokenRequestHandler(handler).ignoringRequestMatchers("/register", "/contact")
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
              //  .addFilterBefore(new RequestValidateFilter(),BasicAuthenticationFilter.class) // just for testing purpose adding a custom filter before authentication filter
                .addFilterAfter(new JwtGenerationFilter(),BasicAuthenticationFilter.class)
                .addFilterBefore(new JwtValidatorFilter() , BasicAuthenticationFilter.class)
                .authorizeHttpRequests(
                        request -> request.requestMatchers("/account").hasRole("USER").requestMatchers("myBalance")
                                .hasAnyRole("USER", "ADMIN").requestMatchers("/loan").hasRole("USER").requestMatchers("/cards")
                                .hasRole("USER").requestMatchers("/user").authenticated()
                                .requestMatchers("/notices", "/contact", "/register").permitAll())
                .formLogin(Customizer.withDefaults()).httpBasic(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
