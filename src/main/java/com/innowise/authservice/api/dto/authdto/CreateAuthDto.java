package com.innowise.authservice.api.dto.authdto;

import lombok.Data;

@Data
public class CreateAuthDto {
    private String email;
    private String password;
}
