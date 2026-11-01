package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Rol;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Genera y valida los JWT de la API.
 *
 * <p>Firma simétrica HS256 con el secreto de {@code jwt.secret}; el algoritmo se declara explícito
 * porque con un secreto de 64 bytes JJWT elegiría HS512 si se omitiera.</p>
 */
@Component
public class JwtUtil {

    private final SecretKey key;
    private final long expiracionMinutos;

    public JwtUtil(@Value("${jwt.secret}") String secret,
                   @Value("${jwt.expiracion-minutos}") long expiracionMinutos) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expiracionMinutos = expiracionMinutos;
    }

    /**
     * Emite un token con {@code sub} = email, claim {@code rol}, {@code iat} y {@code exp}.
     */
    public String generarToken(String email, Rol rol) {
        Instant ahora = Instant.now();
        return Jwts.builder()
                .subject(email)
                .claim("rol", rol.name())
                .issuedAt(Date.from(ahora))
                .expiration(Date.from(ahora.plus(expiracionMinutos, ChronoUnit.MINUTES)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    /**
     * Valida la firma y la vigencia del token.
     *
     * @throws io.jsonwebtoken.JwtException si el token está vencido, mal firmado o malformado
     */
    public Claims validarToken(String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String obtenerEmailDesdeToken(String token) {
        return validarToken(token).getSubject();
    }

    public String obtenerRolDesdeToken(String token) {
        return validarToken(token).get("rol", String.class);
    }
}
