package com.example.spring_security_demo;

import com.example.spring_security_demo.jwt.AuthEntryPointJwt;
import com.example.spring_security_demo.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity //to enable web security features in application as per our needs
@EnableMethodSecurity // Required to be used with @PreAuthorize at method level in controller class
public class SecurityConfig {

    @Autowired
    DataSource dataSource; //we don't need to define dataSource here.
                           //Spring Boot will auto-configure this bean for us based on application.properties file

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(){
        return new AuthTokenFilter();
    }

    //Note that we have added schema.sql file inside resources folder in our project directory because
    //we are using here in-memory h2 database whose contents are cleared once we stop the application.
    //In order to create database schema when we run the application, we need that file.
    //The contents of schema.sql file is taken from the official github repository of Spring Security Project.
    //The contents of scema.sql file can be found at :
    // https://github.com/spring-projects/spring-security/blob/main/core/src/main/resources/org/springframework/security/core/userdetails/jdbc/users.ddl
    // You can alternatively search for "spring security github" on Google
    // and go to "https://github.com/spring-projects/spring-security" which is their official repository
    //in the search box(saying: Go to file) type: "users.ddl" and go on that page to copy its content in schema.sql file

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/h2-console/**").permitAll() //All requests coming to h2 console are
                                                                        // bypassed without security
                .requestMatchers("/signin").permitAll()
                .anyRequest().authenticated());                 //all other requests need proper authentication

        http.sessionManagement(session
                -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));
        //http.formLogin(withDefaults()); //for form based authentication
        //http.httpBasic(withDefaults()); //for non-form based authentication

        http.headers(headers ->
                headers.frameOptions( frameOptions -> frameOptions.sameOrigin()));
        http.csrf(csrf -> csrf.disable());

        http.addFilterBefore(authenticationJwtTokenFilter(), UsernamePasswordAuthenticationFilter.class);
                    //We are adding our own custom filter "authenticationJwtTokenFilter()" just before the
                    //in-built "UsernamePasswordAuthenticationFilter()".
                    //Thereby specifying to SpringSecurity as to exactly when our own
                    //customized filter needs to be executed.
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    public CommandLineRunner initData(UserDetailsService userDetailsService){
        return args -> {
            JdbcUserDetailsManager manager = (JdbcUserDetailsManager) userDetailsService;

            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder().encode("password1"))
                    .roles("USER")
                    .build();

            UserDetails admin = User.withUsername("admin")
                    .password(passwordEncoder().encode("adminPass"))
                    .roles("ADMIN")
                    .build();

            JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
            userDetailsManager.createUser(user1);
            userDetailsManager.createUser(admin);
        };
    }


//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user1 = User.withUsername("user1")
//                .password(passwordEncoder().encode("password1")) //{noop} tells the spring that this particular field should
//                                             //be saved as plaintext
//                .roles("USER")
//                .build(); //constructing a UserDetails object
//
//        UserDetails admin = User.withUsername("admin")
//                .password(passwordEncoder().encode("adminPass"))
//                .roles("ADMIN")
//                .build();
//
//        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
//        userDetailsManager.createUser(user1);
//        userDetailsManager.createUser(admin);
//        return userDetailsManager;
//        //return new InMemoryUserDetailsManager(user1, admin);
//    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception{
        return builder.getAuthenticationManager();
    }

}
