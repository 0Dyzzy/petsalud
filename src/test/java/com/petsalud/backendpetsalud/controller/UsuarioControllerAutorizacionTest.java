package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.security.JwtAuthenticationFilter;
import com.petsalud.backendpetsalud.security.JwtUtil;
import com.petsalud.backendpetsalud.security.SecurityConfig;
import com.petsalud.backendpetsalud.security.UsuarioDetailsService;
import com.petsalud.backendpetsalud.service.UsuarioService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifica la matriz de permisos de {@code /api/usuarios} (Paso 3, D5): listar es solo de ADMIN y
 * {@code GET /{id}} exige ser el propio usuario o ADMIN.
 */
@WebMvcTest(UsuarioController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class})
class UsuarioControllerAutorizacionTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UsuarioService usuarioService;

    @MockBean
    private UsuarioDetailsService usuarioDetailsService;

    @MockBean
    private JwtUtil jwtUtil;

    private Usuario usuario(Long id, String email) {
        return Usuario.builder().id(id).email(email).rol(Rol.CLIENTE).build();
    }

    @Test
    @WithMockUser(username = "cliente@test.cl", authorities = "CLIENTE")
    void deberiaResponder403CuandoClienteListaTodosLosUsuarios() throws Exception {
        mockMvc.perform(get("/api/usuarios"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin@test.cl", authorities = "ADMIN")
    void deberiaResponder200CuandoAdminListaTodosLosUsuarios() throws Exception {
        when(usuarioService.listarUsuarios()).thenReturn(List.of());

        mockMvc.perform(get("/api/usuarios"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "juan@test.cl", authorities = "CLIENTE")
    void deberiaResponder200CuandoClienteConsultaSuPropioUsuario() throws Exception {
        when(usuarioService.obtenerUsuarioPorId(1L)).thenReturn(Optional.of(usuario(1L, "juan@test.cl")));

        mockMvc.perform(get("/api/usuarios/1"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "juan@test.cl", authorities = "CLIENTE")
    void deberiaResponder403CuandoClienteConsultaElUsuarioDeOtro() throws Exception {
        when(usuarioService.obtenerUsuarioPorId(2L)).thenReturn(Optional.of(usuario(2L, "otro@test.cl")));

        mockMvc.perform(get("/api/usuarios/2"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin@test.cl", authorities = "ADMIN")
    void deberiaResponder200CuandoAdminConsultaElUsuarioDeOtro() throws Exception {
        when(usuarioService.obtenerUsuarioPorId(2L)).thenReturn(Optional.of(usuario(2L, "otro@test.cl")));

        mockMvc.perform(get("/api/usuarios/2"))
                .andExpect(status().isOk());
    }
}
