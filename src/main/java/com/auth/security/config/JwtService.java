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

    /**
     * Extracts the Username from the provided JWT Token, using the method extractClaims.
     * @param jwtToken String
     * @return Username as String
     */
    public String extractUsername(String jwtToken) {
        return extractClaims(jwtToken,Claims::getSubject);
    }

    /**
     * Extract a single claim from the JWT Token
     *
     * @param token String
     * @param claimsResolver
     * @return
     *
     */
    public <T> T extractClaims(String token, Function<Claims,T> claimsResolver){
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Calls the generateToken method using a New HashMap and the userDetails
     * @param userDetails User data.
     * @return JWT Token as String.
     */
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    /**
     * Generates a new JWT Token using the user details.
     * The Claims
     * The current date.
     * The expiration date of the Token using the Time from the Properties.
     * Signing the Token
     * @param extractedClaims
     * @param userDetails
     * @return JWT Token as String
     */
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

    /**
     * Calls the generateTokenRefreshToken method using the user details.
     * @param userDetails
     * @return
     */
    public String generateTokenRefreshToken(UserDetails userDetails){
        return generateTokenRefreshToken(new HashMap<>(),userDetails);
    }
    /**
     * Generates a new JWT Token using the user details.
     * The Claims
     * The current date.
     * The expiration date of the Token using the Time from the Properties.
     * Signing the Token
     * @param extractedClaims
     * @param userDetails
     * @return JWT Token as String
     */
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


    /**
     * Validates the expiration date of the token and checks if the username is correct.
     * If not, returns false.
     * @param token String
     * @param userDetails
     * @return Boolean
     */
    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()))&&!isTokenExpired(token);
    }

    /**
     * Checks if the expiration date of the JWT Token is still valid.
     * If not, returns false.
     * @param token String
     * @return Boolean
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Extracts the expiration date of the provided JWT Token
     * @param token String
     * @return Date
     */
    private Date extractExpiration(String token) {
        return extractClaims(token, Claims::getExpiration);
    }

    /**
     * Extract all claims from the JWT Token
     * @param token String
     * @return Claims
     */
    private Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSigninKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Creates a signing key with our Secret Key
     * @return Key
     */
    private Key getSigninKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
