package com.innowise.authservice.api.client;

public record GetCardInfoDto(
    Long id,
    String number,
    String expirationDate
) {}