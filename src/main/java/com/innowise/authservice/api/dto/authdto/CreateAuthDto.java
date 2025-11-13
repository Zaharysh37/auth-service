package com.innowise.authservice.api.dto.authdto;

import java.time.*;
import lombok.Data;

@Data
public class CreateAuthDto {
    private String email;
    private String password;
    private String name;
    private String surname;
    private LocalDate birthDate;
}
