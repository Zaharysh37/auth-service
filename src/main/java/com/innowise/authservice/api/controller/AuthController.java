package com.innowise.authservice.api.controller;

import com.innowise.authservice.api.dto.CreateAuthDto;
import com.innowise.authservice.api.dto.CreateProfileDto;
import com.innowise.authservice.api.dto.GetAuthDto;
import com.innowise.authservice.api.dto.GetRefreshTokenDto;
import com.innowise.authservice.core.dao.CredentialRepository;
import com.innowise.authservice.core.entity.Credential;
import com.innowise.authservice.core.entity.Role;
import com.innowise.authservice.core.service.JwtService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.JwtException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RestTemplate restTemplate;

    @Value("${app.userservice.url:http://localhost:8081/api/users/internal/register}")
    private String userServiceUrl;

    @PostMapping("/login")
    public ResponseEntity<GetAuthDto> login(@RequestBody CreateAuthDto getAuthDto) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                getAuthDto.getEmail(),
                getAuthDto.getPassword()
            )
        );

        if (authentication.isAuthenticated()) {
            Credential credential = (Credential) authentication.getPrincipal();

            Map<String, String> tokens = jwtService.generateTokens(credential);

            return ResponseEntity.ok(
                GetAuthDto.builder()
                    .accessToken(tokens.get("access_token"))
                    .refreshToken(tokens.get("refresh_token"))
                    .build()
            );
        } else {
            throw new UsernameNotFoundException("Invalid credentials");
        }
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody CreateAuthDto createAuthDto) {
        if (credentialRepository.existsByEmail(createAuthDto.getEmail())) {
            return ResponseEntity.status(409).body("Error: Email is already taken!");
        }

        Credential credential = Credential.builder()
            .sub(UUID.randomUUID())
            .email(createAuthDto.getEmail())
            .password(passwordEncoder.encode(createAuthDto.getPassword()))
            .role(Role.ROLE_USER)
            .build();

        CreateProfileDto profileDto = new CreateProfileDto(
            credential.getSub(),
            createAuthDto.getName(),
            createAuthDto.getSurname(),
            createAuthDto.getEmail()
        );

        try {
            restTemplate.postForEntity(userServiceUrl, profileDto, String.class);

            credentialRepository.save(credential);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body("Error: User Profile Service is unavailable. Registration failed. " + e.getMessage());
        }

        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully!");
    }

    @PostMapping("/refresh")
    public ResponseEntity<GetAuthDto> refreshToken(@RequestBody GetRefreshTokenDto dto) {
        String refreshToken = dto.getRefreshToken();

        if (jwtService.isTokenExpired(refreshToken)) {
            throw new JwtException("Refresh token is expired");
        }

        String sub = jwtService.extractSub(refreshToken);

        Credential credential = credentialRepository.findBySub(UUID.fromString(sub))
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Map<String, String> tokens = jwtService.generateTokens(credential);

        return ResponseEntity.ok(
            GetAuthDto.builder()
                .accessToken(tokens.get("access_token"))
                .refreshToken(tokens.get("refresh_token"))
                .build()
        );
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validateToken() {
        return ResponseEntity.ok("Token is valid");
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwtSet() {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) jwtService.getPublicKey())
            .keyID(UUID.randomUUID().toString())
            .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return ResponseEntity.ok(jwkSet.toJSONObject());
    }

    // Эндпоинты /refresh и /validate
}
