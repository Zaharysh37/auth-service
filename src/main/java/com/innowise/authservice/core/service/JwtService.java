package com.innowise.authservice.core.service;

import io.jsonwebtoken.security.SignatureAlgorithm;
import com.innowise.authservice.core.entity.Credential;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

    public static final String KEY_ID = "main-rsa-key";

    private static final SignatureAlgorithm ALGORITHM = Jwts.SIG.RS256;
    private final KeyPair keyPair = ALGORITHM.keyPair().build();
    public final PrivateKey privateKey;
    public final PublicKey publicKey;

    @Value("${jwt.access-token.expiration-minutes:15}")
    private long accessTokenExpirationMinutes;

    @Value("${jwt.refresh-token.expiration-hours:2}")
    private long refreshTokenExpirationDays;

    public JwtService() {
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public Map<String, String> generateTokens(Credential credential, Long userId) {
        String accessToken = buildAccessToken(credential, userId);
        String refreshToken = buildRefreshToken(credential.getSub());

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", accessToken);
        tokens.put("refresh_token", refreshToken);
        return tokens;
    }

    private String buildAccessToken(Credential credential, Long userId) {
        Instant now = Instant.now();

        String scope = credential.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.joining(" "));

        return Jwts.builder()
            .header().keyId(KEY_ID).and()
            .subject(credential.getSub().toString())
            .claim("scope", scope)
            .claim("userId", userId.toString())
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(accessTokenExpirationMinutes, ChronoUnit.MINUTES)))
            .signWith(privateKey, ALGORITHM)
            .compact();
    }

    private String buildRefreshToken(UUID sub) {
        Instant now = Instant.now();
        return Jwts.builder()
            .header().keyId(KEY_ID).and()
            .subject(sub.toString())
            .issuedAt(Date.from(now))
            .expiration(Date.from(now.plus(refreshTokenExpirationDays, ChronoUnit.DAYS)))
            .signWith(privateKey, ALGORITHM)
            .compact();
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
            .verifyWith(publicKey)
            .build()
            .parseSignedClaims(token)
            .getPayload();
    }

    public boolean isTokenExpired(String token) {
        try {
            return extractAllClaims(token).getExpiration().before(new Date());
        } catch (Exception e) {
            return true;
        }
    }

    public String extractSub(String token) {
        return extractAllClaims(token).getSubject();
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }
}
