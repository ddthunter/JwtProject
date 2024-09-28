package com.example.backend.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;

@Component
public class JwtUtils {
    @Value("${spring.security.jwt.key}")
    String key;
    @Value("${spring.security.jwt.expire}")
    Integer expire;

    public DecodedJWT resolveJwt(String token) {
        token = this.convertToken(token);
        if (token == null) return null;
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier verifier = JWT.require(algorithm).build();
        try {
            DecodedJWT verify = verifier.verify(token);
            Date expiresAt = verify.getExpiresAt();
            return new Date().after(expiresAt) ? null : verify;
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    public String createJwt(UserDetails userDetails, Long userId, String username) {
        Algorithm algorithm = Algorithm.HMAC256(key);
        return JWT.create()
                .withClaim("id",userId)
                .withClaim("name", username)
                .withClaim("authorities", userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                .withExpiresAt(this.expiresTime())
                .withIssuedAt(new Date())
                .sign(algorithm);
    }

    public Date expiresTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR, expire * 24);
        return calendar.getTime();
    }

    public UserDetails toUserDetails(DecodedJWT decodedJWT) {
        Map<String, Claim> claims = decodedJWT.getClaims();
        return User
                .withUsername(claims.get("name").asString())
                .password("********")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }
    public Long toUserId(DecodedJWT decodedJWT) {
        Map<String, Claim> claims = decodedJWT.getClaims();
        return claims.get("id").asLong();
    }

    private String convertToken(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
            return token;
        }
        return null;
    }

}
