package com.example.springsecuritybasic.filter;



import com.example.springsecuritybasic.constant.SecurityConstant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JwtValidatorFilter extends OncePerRequestFilter {
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
        return request.getServletPath().equals("/user");
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
        SecretKey key = Keys.hmacShaKeyFor(SecurityConstant.JWT_KEY.getBytes(StandardCharsets.UTF_8));
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        var jwt = request.getHeader(SecurityConstant.JWT_HEADER);
        if(jwt != null){
            try {
                Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(jwt).getPayload();

                String username = String.valueOf(claims.get("username"));
                String authorities = (String) claims.get("authorities");
                Authentication authDetails = new UsernamePasswordAuthenticationToken(username,null, AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
                SecurityContextHolder.getContext().setAuthentication(authDetails);
            } catch(Exception ex){
                throw new BadCredentialsException("Invalid token");
            }
        }
        filterChain.doFilter(request,response);
    }


}
