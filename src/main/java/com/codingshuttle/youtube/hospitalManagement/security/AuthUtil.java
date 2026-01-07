package com.codingshuttle.youtube.hospitalManagement.security;

import com.codingshuttle.youtube.hospitalManagement.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

//primary work to create JWT token
@Component
public class AuthUtil {

    @Value("${jwt.secretKey}")
    private String jwtSecretKey;
    // to convert simple secretKey into hmacSHA format for JWT
    private SecretKey getSecretKey(){
        return Keys.hmacShaKeyFor(jwtSecretKey.getBytes(StandardCharsets.UTF_8));
    }

    //for generating token
    public String generateAccessToken(User user){
        //here we generate JWT
        return Jwts.builder()
                //PAYLOAD
                .subject(user.getUsername())
                .claim("userId", user.getId().toString())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+ 1000*60*10))
                //SECRET(JJWT generates HEADER automatically using signWith)
                .signWith(getSecretKey())
                .compact();
    }

    //for getting the username from token
    public String getUsernameFromToken(String token){
        Claims claims = Jwts.parser()
                .verifyWith(getSecretKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return claims.getSubject();
    }


}
