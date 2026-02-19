package com.innowise.authservice.core.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.innowise.authservice.api.client.GetUserDto;
import com.innowise.authservice.api.client.UserClient;
import com.innowise.authservice.api.dto.GetRefreshTokenDto;
import com.innowise.authservice.api.dto.authdto.CreateAuthDto;
import com.innowise.authservice.api.dto.authdto.GetAuthDto;
import com.innowise.authservice.core.dao.CredentialRepository;
import com.innowise.authservice.core.entity.Credential;
import com.innowise.authservice.core.entity.Role;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import io.jsonwebtoken.JwtException;
import jakarta.persistence.EntityNotFoundException;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final CredentialRepository credentialRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserClient userClient;

    private final Cache<String, Long> emailToUserIdCache =
        Caffeine.newBuilder()
            .expireAfterWrite(2, TimeUnit.HOURS)
            .maximumSize(1000)
            .build();

    @Transactional
    public GetAuthDto login(CreateAuthDto createAuthDto) {

        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(
                createAuthDto.getEmail(),
                createAuthDto.getPassword()
            )
        );

        if (authentication.isAuthenticated()) {

            Credential credential = (Credential) authentication.getPrincipal();

            Long userId = getUserIdByEmail(createAuthDto.getEmail());

            Map<String, String> tokens = jwtService.generateTokens(credential, userId);

            return GetAuthDto.builder()
                    .accessToken(tokens.get("access_token"))
                    .refreshToken(tokens.get("refresh_token"))
                    .build();
        } else {
            throw new UsernameNotFoundException("Invalid credentials");
        }
    }

    @Transactional
    public UUID register(CreateAuthDto createAuthDto) {

        UUID uuid = UUID.randomUUID();

        Credential credential = Credential.builder()
            .sub(uuid)
            .email(createAuthDto.getEmail())
            .password(passwordEncoder.encode(createAuthDto.getPassword()))
            .role(Role.ROLE_USER)
            .build();

        credentialRepository.save(credential);

        return uuid;
    }

    @Transactional
    public GetAuthDto refreshToken(GetRefreshTokenDto dto) {

        String refreshToken = dto.getRefreshToken();

        if (jwtService.isTokenExpired(refreshToken)) {
            throw new JwtException("Refresh token is expired");
        }

        String sub = jwtService.extractSub(refreshToken);

        Credential credential = credentialRepository.findBySub(UUID.fromString(sub))
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        Long userId = getUserIdByEmail(credential.getEmail());

        Map<String, String> tokens = jwtService.generateTokens(credential, userId);

        return GetAuthDto.builder()
                .accessToken(tokens.get("access_token"))
                .refreshToken(tokens.get("refresh_token"))
                .build();
    }

    @Transactional
    public void deleteUserBySub(UUID sub) {

        Credential existingCred = credentialRepository.findBySub(sub)
            .orElseThrow(() -> new EntityNotFoundException("User not found with sub: " + sub));
        credentialRepository.delete(existingCred);
        updateUserCache(existingCred.getEmail());
    }

    public Map<String, Object> getJwtSet() {

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) jwtService.getPublicKey())
            .keyID(JwtService.KEY_ID)
            .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return jwkSet.toJSONObject();
    }

    Long getUserIdByEmail(String email) {
        return emailToUserIdCache.get(email, kkey -> {
            GetUserDto getUserDto = userClient.getUserByEmail(email);
            return getUserDto.id();
        });
    }

    public void updateUserCache(String email) {
        emailToUserIdCache.invalidate(email);
    }
}
