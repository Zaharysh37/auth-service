package com.innowise.authservice.api.dto;

import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateProfileDto {
    private UUID sub;
    private String name;
    private String surname;
    private String email;
}
