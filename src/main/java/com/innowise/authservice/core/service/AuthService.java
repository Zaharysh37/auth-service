package com.innowise.authservice.core.service;

import com.innowise.authservice.api.dto.CreateProfileDto;
import com.innowise.authservice.api.dto.GetRefreshTokenDto;
import com.innowise.authservice.api.dto.authdto.CreateAuthDto;
import com.innowise.authservice.api.dto.authdto.GetAuthDto;
import com.innowise.authservice.core.dao.CredentialRepository;
import com.innowise.authservice.core.entity.Credential;
import com.innowise.authservice.core.entity.Role;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.JwtException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RestTemplate restTemplate;

    @Value("${app.userservice.url:http://localhost:8081/api/users/internal/register}")
    private String userServiceUrl;

    public GetAuthDto login(CreateAuthDto getAuthDto) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                getAuthDto.getEmail(),
                getAuthDto.getPassword()
            )
        );

        if (authentication.isAuthenticated()) {
            Credential credential = (Credential) authentication.getPrincipal();

            Map<String, String> tokens = jwtService.generateTokens(credential);

            return GetAuthDto.builder()
                    .accessToken(tokens.get("access_token"))
                    .refreshToken(tokens.get("refresh_token"))
                    .build();
        } else {
            throw new UsernameNotFoundException("Invalid credentials");
        }
    }

    public boolean register(CreateAuthDto createAuthDto) {

        Credential credential = Credential.builder()
            .sub(UUID.randomUUID())
            .email(createAuthDto.getEmail())
            .password(passwordEncoder.encode(createAuthDto.getPassword()))
            .role(Role.ROLE_USER)
            .build();

        CreateProfileDto profileDto = CreateProfileDto.builder()
            .sub(credential.getSub())
            .name(createAuthDto.getName())
            .surname(createAuthDto.getSurname())
            .birthDate(createAuthDto.getBirthDate())
            .email(createAuthDto.getEmail())
            .build();

        try {
            restTemplate.postForEntity(userServiceUrl, profileDto, String.class);

            credentialRepository.save(credential);
        } catch (Exception e) {
            return false;

        }

        return true;
    }

    public GetAuthDto refreshToken(GetRefreshTokenDto dto) {
        String refreshToken = dto.getRefreshToken();

        if (jwtService.isTokenExpired(refreshToken)) {
            throw new JwtException("Refresh token is expired");
        }

        String sub = jwtService.extractSub(refreshToken);

        Credential credential = credentialRepository.findBySub(UUID.fromString(sub))
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Map<String, String> tokens = jwtService.generateTokens(credential);

        return GetAuthDto.builder()
                .accessToken(tokens.get("access_token"))
                .refreshToken(tokens.get("refresh_token"))
                .build();
    }

    public Map<String, Object> getJwtSet() {
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) jwtService.getPublicKey())
            .keyID(JwtService.KEY_ID)
            .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return jwkSet.toJSONObject();
    }
}
