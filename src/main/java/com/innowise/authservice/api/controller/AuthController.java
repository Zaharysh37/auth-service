package com.innowise.authservice.api.controller;

import com.innowise.authservice.api.dto.GetRefreshTokenDto;
import com.innowise.authservice.api.dto.authdto.CreateAuthDto;
import com.innowise.authservice.api.dto.authdto.GetAuthDto;
import com.innowise.authservice.core.service.AuthService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public ResponseEntity<GetAuthDto> login(@RequestBody CreateAuthDto getAuthDto) {
        return ResponseEntity.ok(authService.login(getAuthDto));
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody CreateAuthDto createAuthDto) {
        if (authService.register(createAuthDto)) return ResponseEntity.status(HttpStatus.CREATED)
            .body("User registered successfully!");
        else return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
            .body("Error: User Profile Service is unavailable. Registration failed.");
    }

    @PostMapping("/refresh")
    public ResponseEntity<GetAuthDto> refreshToken(@RequestBody GetRefreshTokenDto dto) {
        return ResponseEntity.ok(authService.refreshToken(dto));
    }

    @GetMapping("/validate")
    public ResponseEntity<String> validateToken() {
        return ResponseEntity.ok("Token is valid");
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwtSet() {
        return ResponseEntity.ok(authService.getJwtSet());
    }
}
