package com.domainizer.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.domainizer.administration.model.UserData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.sql.Date;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

@Component
public class JwtProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    public String generateToken(UserData userData) {
        Algorithm algorithm = Algorithm.HMAC512(getSecretKey());
        return JWT.create()
                .withIssuer("domainizer")
                .withExpiresAt(Date.from(Instant.now().plus(Duration.ofHours(1))))
                .withClaim("username", userData.getUsername())
                .withClaim("userRole", userData.getRole().toString())
                .sign(algorithm);
    }

    public boolean validateToken(String token) {
        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC512(getSecretKey()))
                    .build();
            verifier.verify(token);
            return true;
        } catch (JWTDecodeException e) {
            logger.error("Error while decoding JWT");
            logger.error(Arrays.toString(e.getStackTrace()));
        }
        return false;
    }

    public Authentication getAuthentication(String token) {
        Collection<GrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority(JWT.decode(token).getClaim("userRole").asString())
        );
        String username = JWT.decode(token).getClaim("username").asString();
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

    private byte[] getSecretKey() {
        File key = new File("jwt.key");
        byte[] result = new byte[512];
        try {
            FileInputStream fis = new FileInputStream(key);
            result = fis.readAllBytes();
        } catch (Exception ignored) {

        }
        return result;
    }
}
