package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Usuario;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Login: valida credenciales contra la BD (vía {@link AuthenticationManager}) y emite un JWT.
 */
@RestController
public class AuthController {

    private static final String ERROR_CREDENCIALES = "Credenciales invalidas";

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/api/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest loginRequest) {
        if (loginRequest == null || esVacio(loginRequest.email()) || esVacio(loginRequest.password())) {
            return respuestaNoAutorizado();
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password()));

            UsuarioDetails usuarioDetails = (UsuarioDetails) authentication.getPrincipal();
            Usuario usuario = usuarioDetails.getUsuario();

            String token = jwtUtil.generarToken(usuario.getEmail(), usuario.getRol());

            return ResponseEntity.ok(Map.of(
                    "token", token,
                    "rol", usuario.getRol().name(),
                    "email", usuario.getEmail()));
        } catch (AuthenticationException ex) {
            return respuestaNoAutorizado();
        }
    }

    private ResponseEntity<Map<String, String>> respuestaNoAutorizado() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", ERROR_CREDENCIALES));
    }

    private boolean esVacio(String valor) {
        return valor == null || valor.isBlank();
    }
}
