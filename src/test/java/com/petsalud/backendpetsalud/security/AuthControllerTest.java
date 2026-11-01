package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests de AuthController con MockMvc standalone: sin base de datos ni cadena de seguridad.
 */
@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtUtil jwtUtil;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        AuthController authController = new AuthController();
        ReflectionTestUtils.setField(authController, "authenticationManager", authenticationManager);
        ReflectionTestUtils.setField(authController, "jwtUtil", jwtUtil);
        mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
    }

    @Test
    void deberiaDevolverTokenRolYEmailCuandoLasCredencialesSonValidas() throws Exception {
        Usuario usuario = Usuario.builder()
                .email("juan@test.cl")
                .password("$2a$10$hash")
                .rol(Rol.CLIENTE)
                .build();
        UsuarioDetails usuarioDetails = new UsuarioDetails(usuario);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                usuarioDetails, null, usuarioDetails.getAuthorities());

        when(authenticationManager.authenticate(any())).thenReturn(authentication);
        when(jwtUtil.generarToken("juan@test.cl", Rol.CLIENTE)).thenReturn("token-falso");

        mockMvc.perform(post("/api/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"juan@test.cl\",\"password\":\"1234\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("token-falso"))
                .andExpect(jsonPath("$.rol").value("CLIENTE"))
                .andExpect(jsonPath("$.email").value("juan@test.cl"));
    }

    @Test
    void deberiaDevolver401CuandoLasCredencialesSonInvalidas() throws Exception {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("Credenciales invalidas"));

        mockMvc.perform(post("/api/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"juan@test.cl\",\"password\":\"incorrecta\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Credenciales invalidas"));
    }

    @Test
    void deberiaDevolver401CuandoFaltaElPassword() throws Exception {
        mockMvc.perform(post("/api/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"juan@test.cl\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Credenciales invalidas"));
    }
}
