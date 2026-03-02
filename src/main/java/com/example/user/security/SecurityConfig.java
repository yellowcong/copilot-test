package com.example.user.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final Environment environment;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        boolean isDevProfile = environment.acceptsProfiles(
                org.springframework.core.env.Profiles.of("dev", "default"));
        
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                auth.requestMatchers("/api/auth/**").permitAll();
                
                // H2 console is disabled via configuration; always deny access
                auth.requestMatchers("/h2-console/**").denyAll();
                
                // Actuator: allow health check in dev, deny all in other profiles
                if (isDevProfile) {
                    auth.requestMatchers("/actuator/health").permitAll();
                } else {
                    auth.requestMatchers("/actuator/**").denyAll();
                }
                
                // Only ADMIN can access user CRUD operations
                auth.requestMatchers(HttpMethod.GET, "/api/users/**").hasRole("ADMIN");
                auth.requestMatchers(HttpMethod.POST, "/api/users").hasRole("ADMIN");
                auth.requestMatchers(HttpMethod.PUT, "/api/users/**").hasRole("ADMIN");
                auth.requestMatchers(HttpMethod.DELETE, "/api/users/**").hasRole("ADMIN");
                
                auth.anyRequest().authenticated();
            })
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        // Only disable frameOptions in dev profile
        if (isDevProfile) {
            http.headers(headers -> headers.frameOptions(frame -> frame.disable()));
        } else {
            http.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));
        }
        
        return http.build();
    }
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
