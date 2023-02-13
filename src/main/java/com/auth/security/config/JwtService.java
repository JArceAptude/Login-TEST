package com.auth.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {
    @Value("${airlines.app.jwtSecret}")
    private String SECRET_KEY;
    @Value("${airlines.app.expiration}")
    private Long expiration;

    @Value("${airlines.app.refreshtoken}")
    private Long expirationRefreshToken;
    public String extractUsername(String jwtToken) {
        return extractClaims(jwtToken,Claims::getSubject);
    }

    public <T> T extractClaims(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(Map<String,Object> extractedClaims, UserDetails userDetails){
        return Jwts.builder()
                .setClaims(extractedClaims)
                .setSubject(userDetails.getUsername())
                .claim("authorities",userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+expiration*60*24))
                .signWith(getSigninKey(), SignatureAlgorithm.HS512)
                .compact();
    }

    public String generateTokenRefreshToken(UserDetails userDetails){
        return generateTokenRefreshToken(new HashMap<>(),userDetails);
    }

    public String generateTokenRefreshToken(Map<String,Object> extractedClaims, UserDetails userDetails){
        return Jwts.builder()
                .setClaims(extractedClaims)
                .setSubject(userDetails.getUsername())
                .claim("authorities",userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+expirationRefreshToken*60*24))
                .signWith(getSigninKey(), SignatureAlgorithm.HS512)
                .compact();
    }


    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()))&&!isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
