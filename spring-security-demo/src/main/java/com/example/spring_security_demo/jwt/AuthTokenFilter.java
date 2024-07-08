package com.example.spring_security_demo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {//Our customized filter to intercept all incoming
                                                            //requests to check if Token is valid

    @Autowired
    private JwtUtils jwtUtils; //JwtUtils is our Spring Managed Component

    @Autowired
    private UserDetailsService userDetailsService; //UserDetailsService is an in-built interface

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);
    //Logger is not mandatory. We can skip it if we want to. It is just for debugging purposes.

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        //We need to override doFilterInternal() always when using OncePerRequestFilter()

        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());

        try {
            String jwt = parseJwt(request); //extracting the JWT Token using parseJwt(), our own method
            if (jwt != null && jwtUtils.validateJwtToken(jwt)){
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                                                            userDetails, null, userDetails.getAuthorities());
                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    //We are enhancing the authentication token object details here with additional details like
                    //session ID etc. that we are getting from the request.

                SecurityContextHolder.getContext().setAuthentication(authentication);
                    //Here, we are effectively authenticating the user for the duration of the request & setting him in
                    //the security context.
            }
        } catch (Exception e){
            logger.error("Cannot set user authentication: {}", e);
        }

        filterChain.doFilter(request, response);
                //We are instructing the Spring to continue the filter chain as usual.
                //Why? ===> bcz we have added our own customized filter: "AuthTokenFilter" in between.
                //This line also tells Spring that user defined custom filter is done with its processing.
    }

    private String parseJwt(HttpServletRequest request){
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}
