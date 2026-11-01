package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Rol;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests de JwtUtil sin contexto de Spring ni base de datos.
 */
class JwtUtilTest {

    private static final String SECRETO = "2d8c2741376ef14635406c17d10228ac904920102acfdadfb066bafad92d0eb5";
    private static final String OTRO_SECRETO = "1111111111111111111111111111111111111111111111111111111111111111";

    private final JwtUtil jwtUtil = new JwtUtil(SECRETO, 60);

    @Test
    void deberiaGenerarTokenFirmadoConHS256ConEmailRolYFechas() {
        String token = jwtUtil.generarToken("juan@test.cl", Rol.CLIENTE);

        assertNotNull(token);

        Claims claims = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(SECRETO.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseSignedClaims(token)
                .getPayload();

        assertEquals("juan@test.cl", claims.getSubject());
        assertEquals("CLIENTE", claims.get("rol", String.class));
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
        assertTrue(claims.getExpiration().after(claims.getIssuedAt()));

        String algoritmo = Jwts.parser()
                .verifyWith(Keys.hmacShaKeyFor(SECRETO.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseSignedClaims(token)
                .getHeader()
                .getAlgorithm();
        assertEquals("HS256", algoritmo);
    }

    @Test
    void deberiaExponerEmailYRolDesdeLosHelpers() {
        String token = jwtUtil.generarToken("admin@test.cl", Rol.ADMIN);

        assertEquals("admin@test.cl", jwtUtil.obtenerEmailDesdeToken(token));
        assertEquals("ADMIN", jwtUtil.obtenerRolDesdeToken(token));
    }

    @Test
    void deberiaRechazarTokenFirmadoConOtroSecreto() {
        String token = new JwtUtil(OTRO_SECRETO, 60).generarToken("juan@test.cl", Rol.CLIENTE);

        assertThrows(SignatureException.class, () -> jwtUtil.validarToken(token));
    }

    @Test
    void deberiaRechazarTokenExpirado() {
        String token = new JwtUtil(SECRETO, -1).generarToken("juan@test.cl", Rol.CLIENTE);

        assertThrows(ExpiredJwtException.class, () -> jwtUtil.validarToken(token));
    }

    @Test
    void deberiaRechazarTokenMalformado() {
        assertThrows(JwtException.class, () -> jwtUtil.validarToken("basura"));
    }
}
