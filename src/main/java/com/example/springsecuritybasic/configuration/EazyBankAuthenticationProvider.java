package com.example.springsecuritybasic.configuration;

import com.example.springsecuritybasic.repository.CustomerRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.ArrayList;

@Component
public class EazyBankAuthenticationProvider implements AuthenticationProvider {


    private final CustomerRepository customerRepository;
    private final PasswordEncoder encoder;

    public EazyBankAuthenticationProvider(CustomerRepository customerRepository, PasswordEncoder encoder) {
        this.customerRepository = customerRepository;
        this.encoder = encoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var presentedUserName = authentication.getName();
        var presentedPwd = authentication.getCredentials().toString();
        var userDetails = customerRepository.findByEmail(presentedUserName);
        if(userDetails.size()>0){
            if(encoder.matches(presentedPwd,userDetails.get(0).getPwd())){
                var authRoles = new ArrayList<GrantedAuthority>();
                authRoles.add(new SimpleGrantedAuthority(userDetails.get(0).getRole()));
                return new UsernamePasswordAuthenticationToken(presentedUserName,presentedPwd,authRoles);
            }
            else{
                throw new BadCredentialsException("Bad credential , Invalid password");
            }
        }
        else{
            throw new BadCredentialsException("User not found");
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
