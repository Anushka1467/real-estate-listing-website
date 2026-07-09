package com.realestate.listing.config;

import com.realestate.listing.security.CustomUserDetailsService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    private final CustomUserDetailsService customUserDetailsService;

    public SecurityConfig(CustomUserDetailsService customUserDetailsService) {
        this.customUserDetailsService = customUserDetailsService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(csrf -> csrf.disable())

                .authorizeHttpRequests(auth -> auth

                        // Public Pages
                        .requestMatchers(
                                "/",
                                "/login",
                                "/signup",
                                "/register",
                                "/style.css",
                                "/js/**",
                                "/images/**"
                        ).permitAll()

                        // Only authenticated users can access property pages
                        .requestMatchers("/properties/**").authenticated()

                        .anyRequest().authenticated()
                )

                .formLogin(login -> login

                        .loginPage("/login")

                        // Redirect to Home after successful login
                        .defaultSuccessUrl("/", true)

                        .permitAll()
                )

                .logout(logout -> logout

                        // Redirect to Home after logout
                        .logoutSuccessUrl("/")

                        .invalidateHttpSession(true)

                        .deleteCookies("JSESSIONID")

                        .permitAll()
                )

                .userDetailsService(customUserDetailsService);

        return http.build();
    }
}