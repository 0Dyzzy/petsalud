package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.entity.Producto;
import com.petsalud.backendpetsalud.security.JwtAuthenticationFilter;
import com.petsalud.backendpetsalud.security.JwtUtil;
import com.petsalud.backendpetsalud.security.SecurityConfig;
import com.petsalud.backendpetsalud.security.UsuarioDetailsService;
import com.petsalud.backendpetsalud.service.ProductoService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Test de muestra del Paso 3 (autorización por rol): el catálogo se lee con cualquier rol
 * autenticado, pero solo ADMIN puede escribir. Sin base de datos.
 */
@WebMvcTest(ProductoController.class)
@Import({SecurityConfig.class, JwtAuthenticationFilter.class})
class ProductoControllerAutorizacionTest {

    private static final String PRODUCTO_JSON = """
            {"nombre":"Alimento","descripcion":"Saco 10kg","precio":19990,"stock":5,"categoria":"Alimentos"}
            """;

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ProductoService productoService;

    @MockBean
    private UsuarioDetailsService usuarioDetailsService;

    @MockBean
    private JwtUtil jwtUtil;

    @Test
    @WithMockUser(username = "cliente@test.cl", authorities = "CLIENTE")
    void deberiaResponder403CuandoClienteCreaProducto() throws Exception {
        mockMvc.perform(post("/api/productos")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(PRODUCTO_JSON))
                .andExpect(status().isForbidden());

        verify(productoService, never()).agregarProducto(any());
    }

    @Test
    @WithMockUser(username = "admin@test.cl", authorities = "ADMIN")
    void deberiaResponder200CuandoAdminCreaProducto() throws Exception {
        Producto guardado = Producto.builder()
                .id(1L)
                .nombre("Alimento")
                .precio(new BigDecimal("19990"))
                .stock(5)
                .categoria("Alimentos")
                .build();

        when(productoService.agregarProducto(any(Producto.class))).thenReturn(guardado);

        mockMvc.perform(post("/api/productos")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(PRODUCTO_JSON))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "veterinario@test.cl", authorities = "VETERINARIO")
    void deberiaResponder403CuandoVeterinarioEliminaProducto() throws Exception {
        mockMvc.perform(delete("/api/productos/1"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "cliente@test.cl", authorities = "CLIENTE")
    void deberiaResponder200CuandoClienteListaElCatalogo() throws Exception {
        when(productoService.listarProductos()).thenReturn(java.util.List.of());

        mockMvc.perform(get("/api/productos"))
                .andExpect(status().isOk());
    }

    @Test
    void deberiaResponder401SinTokenAunqueElRolNoSeConozca() throws Exception {
        mockMvc.perform(get("/api/productos"))
                .andExpect(status().isUnauthorized());
    }
}
