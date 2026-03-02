package com.example.user.controller;

import com.example.user.auth.LoginRequest;
import com.example.user.auth.LoginResponse;
import com.example.user.entity.User;
import com.example.user.repository.UserRepository;
import com.example.user.security.JwtUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        // Use generic message to prevent user enumeration
        User user = userRepository.findByEmail(request.getEmail()).orElse(null);
        
        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
        
        String token = jwtUtils.generateToken(user.getEmail(), user.getId());
        
        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setEmail(user.getEmail());
        response.setName(user.getName());
        response.setUserId(user.getId());
        
        return ResponseEntity.ok(response);
    }
    
    @PostMapping("/register")
    public ResponseEntity<LoginResponse> register(@Valid @RequestBody LoginRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            return ResponseEntity.status(HttpStatus.CONFLICT).build();
        }
        
        User user = new User();
        // Safely handle email parsing
        String name = request.getEmail() != null && request.getEmail().contains("@") 
            ? request.getEmail().split("@")[0] 
            : "User";
        user.setName(name);
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRole("USER"); // Default role
        
        User savedUser = userRepository.save(user);
        
        String token = jwtUtils.generateToken(savedUser.getEmail(), savedUser.getId());
        
        LoginResponse response = new LoginResponse();
        response.setToken(token);
        response.setEmail(savedUser.getEmail());
        response.setName(savedUser.getName());
        response.setUserId(savedUser.getId());
        
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }
}
