package com.example.springsecuritybasic.configuration;

import com.example.springsecuritybasic.model.Authority;
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
import java.util.List;
import java.util.Set;

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
                return new UsernamePasswordAuthenticationToken(presentedUserName,presentedPwd,getGrantedAuthorities(userDetails.get(0).getAuthority()));
            }
            else{
                throw new BadCredentialsException("Bad credential , Invalid password");
            }
        }
        else{
            throw new BadCredentialsException("User not found");
        }
    }

    public List<GrantedAuthority> getGrantedAuthorities(Set<Authority>authorities){
        var auth = new ArrayList<GrantedAuthority>();
        for(Authority authZ : authorities){
            auth.add(new SimpleGrantedAuthority(authZ.getName()));
        }
        return auth;
    }

     @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
