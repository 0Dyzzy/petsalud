package com.petsalud.backendpetsalud.security;

/**
 * Body de {@code POST /api/login}. Record mínimo y local: el proyecto no tiene capa DTO.
 */
public record LoginRequest(String email, String password) {
}
