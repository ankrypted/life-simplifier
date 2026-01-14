package com.lifesimplifier.life_simplifier_api.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;

public class JwtUtil {

    // Must be at least 256 bits for HS256
    private static final String SECRET =
            "super-secret-key-super-secret-key-123456";

    private static final Key KEY =
            Keys.hmacShaKeyFor(SECRET.getBytes());

    private static final long EXPIRATION_MS = 30 * 60 * 1000; // 30 minutes

    public static String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(
                        new Date(System.currentTimeMillis() + EXPIRATION_MS)
                )
                .signWith(KEY)
                .compact();
    }

    public static String extractUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public static String extractRole(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(KEY)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .get("role", String.class);
    }
}