package com.innowise.authservice.api.dto;

import lombok.Data;

@Data
public class CreateAuthDto {
    private String email;
    private String password;
    private String name;
    private String surname;
}
