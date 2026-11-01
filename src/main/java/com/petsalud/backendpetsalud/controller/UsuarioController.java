package com.petsalud.backendpetsalud.controller;

import com.petsalud.backendpetsalud.entity.Usuario;
import com.petsalud.backendpetsalud.service.UsuarioService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * CRUD de usuarios con autorización por rol (Paso 3).
 *
 * <p>El registro es público (lo permite {@code SecurityConfig}); todo lo demás exige autenticación y
 * las operaciones de administración exigen {@code ADMIN}. Sobre {@code GET/PUT /{id}} se aplica
 * además verificación de propiedad: un usuario no administrador solo puede operar sobre sí mismo.</p>
 */
@RestController
@RequestMapping("/api/usuarios")
public class UsuarioController {

    private static final String ADMIN = "ADMIN";

    @Autowired
    private UsuarioService usuarioService;

    @PostMapping("/registro")
    public ResponseEntity<Usuario> registrarUsuario(@RequestBody Usuario usuario) {
        Usuario nuevoUsuario = usuarioService.registrarUsuario(usuario);
        return ResponseEntity.ok(nuevoUsuario);
    }

    @GetMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Usuario> obtenerUsuarioPorId(@PathVariable Long id, Authentication authentication) {
        verificarPropietarioOAdmin(id, authentication);
        return usuarioService.obtenerUsuarioPorId(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{id}")
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<Usuario> actualizarUsuario(@PathVariable Long id, @RequestBody Usuario usuario,
                                                     Authentication authentication) {
        verificarPropietarioOAdmin(id, authentication);
        Usuario usuarioActualizado = usuarioService.actualizarUsuario(id, usuario);
        return ResponseEntity.ok(usuarioActualizado);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<Void> eliminarUsuario(@PathVariable Long id) {
        usuarioService.eliminarUsuario(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<Usuario>> listarUsuarios() {
        List<Usuario> usuarios = usuarioService.listarUsuarios();
        return ResponseEntity.ok(usuarios);
    }

    /**
     * Verificación de propiedad: {@code ADMIN} puede operar sobre cualquier usuario; el
     * resto solo si el email autenticado coincide con el del usuario pedido.
     */
    private void verificarPropietarioOAdmin(Long id, Authentication authentication) {
        boolean esAdmin = authentication.getAuthorities().stream()
                .anyMatch(authority -> ADMIN.equals(authority.getAuthority()));

        if (esAdmin) {
            return;
        }

        boolean esPropietario = usuarioService.obtenerUsuarioPorId(id)
                .map(usuario -> authentication.getName().equalsIgnoreCase(usuario.getEmail()))
                .orElse(false);

        if (!esPropietario) {
            throw new AccessDeniedException("Solo puedes acceder a tu propio usuario");
        }
    }
}
