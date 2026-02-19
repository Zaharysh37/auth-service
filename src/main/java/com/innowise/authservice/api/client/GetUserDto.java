package com.innowise.authservice.api.client;

import java.time.LocalDate;
import java.util.List;

public record GetUserDto(
    Long id,
    String name,
    String surname,
    LocalDate birthDate,
    String email,
    List<GetCardInfoDto> cards
) {}
