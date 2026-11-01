package com.petsalud.backendpetsalud.security;

import com.petsalud.backendpetsalud.controller.ProductoController;
import com.petsalud.backendpetsalud.entity.Rol;
import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.service.ProductoService;
import io.jsonwebtoken.MalformedJwtException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Verifica la cadena de seguridad sin base de datos: JWT habilita el acceso, la ausencia de token
 * produce 401 y HTTP Basic ya no autentica.
 */
@WebMvcTest(ProductoController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class})
class SecurityConfigTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ProductoService productoService;

    @MockBean
    private UsuarioDetailsService usuarioDetailsService;

    @MockBean
    private JwtUtil jwtUtil;

    @Test
    void deberiaResponder401CuandoNoSeEnviaToken() throws Exception {
        mockMvc.perform(get("/api/productos"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deberiaResponder401CuandoElTokenEsInvalido() throws Exception {
        when(jwtUtil.obtenerEmailDesdeToken("basura"))
                .thenThrow(new MalformedJwtException("Token invalido"));

        mockMvc.perform(get("/api/productos").header("Authorization", "Bearer basura"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deberiaResponder200CuandoElTokenEsValido() throws Exception {
        Usuario usuario = Usuario.builder()
                .email("juan@test.cl")
                .password("$2a$10$hash")
                .rol(Rol.CLIENTE)
                .build();

        when(jwtUtil.obtenerEmailDesdeToken("token-valido")).thenReturn("juan@test.cl");
        when(usuarioDetailsService.loadUserByUsername("juan@test.cl"))
                .thenReturn(new UsuarioDetails(usuario));
        when(productoService.listarProductos()).thenReturn(List.of());

        mockMvc.perform(get("/api/productos").header("Authorization", "Bearer token-valido"))
                .andExpect(status().isOk());
    }

    @Test
    void noDeberiaAutenticarConHttpBasic() throws Exception {
        mockMvc.perform(get("/api/productos").with(httpBasic("juan@test.cl", "1234")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void deberiaDejarPasarLasRutasPublicasSinToken() throws Exception {
        // /api/login está en permitAll: la petición llega al DispatcherServlet y no la corta la capa
        // de seguridad con 401. El 404 se debe a que este slice solo registra ProductoController.
        mockMvc.perform(post("/api/login"))
                .andExpect(status().isNotFound());
    }
}
