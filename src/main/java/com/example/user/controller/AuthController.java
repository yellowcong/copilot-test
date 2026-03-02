package com.example.user.controller;

import com.example.user.auth.LoginRequest;
import com.example.user.auth.LoginResponse;
import com.example.user.entity.User;
import com.example.user.repository.UserRepository;
import com.example.user.security.JwtUtils;
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
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("User not found with email: " + request.getEmail()));
        
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid password");
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
    public ResponseEntity<LoginResponse> register(@RequestBody LoginRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists: " + request.getEmail());
        }
        
        User user = new User();
        user.setName(request.getEmail().split("@")[0]);
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        
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
