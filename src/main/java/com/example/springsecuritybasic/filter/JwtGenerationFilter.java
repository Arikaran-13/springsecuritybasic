package com.example.springsecuritybasic.filter;

import com.example.springsecuritybasic.constant.SecurityConstant;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.LogManager;
import java.util.logging.Logger;

public class JwtGenerationFilter extends OncePerRequestFilter {

    private Logger log = LogManager.getLogManager().getLogger(JwtGenerationFilter.class.getName());
    /**
     * Can be overridden in subclasses for custom filtering control,
     * returning {@code true} to avoid filtering of the given request.
     * <p>The default implementation always returns {@code false}.
     *
     * @param request current HTTP request
     * @return whether the given request should <i>not</i> be filtered
     * @throws ServletException in case of errors
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !request.getServletPath().equals("/user");
    }

    /**
     * Same contract as for {@code doFilter}, but guaranteed to be
     * just invoked once per request within a single request thread.
     * See {@link #shouldNotFilterAsyncDispatch()} for details.
     * <p>Provides HttpServletRequest and HttpServletResponse arguments instead of the
     * default ServletRequest and ServletResponse ones.
     *
     * @param request
     * @param response
     * @param filterChain
     */

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var authentication = SecurityContextHolder.getContext().getAuthentication(); // after authentication getting authentication object from security context
        SecretKey key = Keys.hmacShaKeyFor(SecurityConstant.JWT_KEY.getBytes(StandardCharsets.UTF_8)); // signature part of jwt
        var jwtToken = Jwts.builder() // building jwt token
                .issuer("Arikaran")
                .subject("JwtToken")
                .claim("username",authentication.getName()) // user name
                .claim("authorities", populateAuthorities(authentication.getAuthorities())) // authorities of the user
                .issuedAt(new Date()) // token creation date
                .expiration(new Date(new Date().getTime()+30000000)) // setting the expiration of the token
                .signWith(key)   // digitally spring security signing with this key
                .compact();
        response.setHeader(SecurityConstant.JWT_HEADER,jwtToken);
       // sending back the response the jwt token in response header
       // log.info("JWT TOKEN : "+jwtToken);
        filterChain.doFilter(request,response); // calling next filter in security filter chain

    }

    public String populateAuthorities(Collection<? extends GrantedAuthority> grantedAuthorities){

        Set<String> authorities = new HashSet<>();

        for(GrantedAuthority authority : grantedAuthorities){
            authorities.add(authority.getAuthority());
        }
        return String.join(",",authorities);
    }


}
