package com.example.user.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtils {
    
    @Value("${jwt.secret:}")
    private String secret;
    
    @Value("${jwt.expiration:86400000}")
    private Long expiration;
    
    private SecretKey signingKey;
    
    @PostConstruct
    public void init() {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("JWT secret must be configured via jwt.secret property or JWT_SECRET environment variable");
        }
        if (secret.length() < 32) {
            throw new IllegalStateException("JWT secret must be at least 32 characters long for HS256");
        }
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }
    
    private SecretKey getSigningKey() {
        return signingKey;
    }
    
    public String generateToken(String email, Long userId) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expiration);
        
        return Jwts.builder()
                .subject(email)
                .claim("userId", userId)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(getSigningKey())
                .compact();
    }
    
    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }
    
    public boolean validateToken(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        try {
            Jwts.parser()
                    .verifyWith(getSigningKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException | MalformedJwtException | UnsupportedJwtException | SignatureException e) {
            return false;
        }
    }
}
