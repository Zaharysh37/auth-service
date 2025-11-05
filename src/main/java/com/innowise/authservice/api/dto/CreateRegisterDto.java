package com.innowise.authservice.api.dto;

import lombok.Data;

@Data
public class CreateRegisterDto {
    private String email;
    private String password;
    private String name;
    private String surname;
    //field for UserService
}
