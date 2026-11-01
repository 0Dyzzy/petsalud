package com.petsalud.backendpetsalud.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

/**
 * Seguridad de la API stateless, autenticación por JWT (header Bearer).
 *
 * <p>HTTP Basic y CSRF quedan deshabilitados: no hay sesión ni cookie de sesión que proteger.</p>
 *
 * <p>La autorización por rol se declara con {@code @PreAuthorize} en cada controller (Paso 3);
 * {@link EnableMethodSecurity} es lo que la activa. Las reglas de ruta se mantienen solo para las
 * rutas públicas y como red de seguridad ({@code anyRequest().authenticated()}).</p>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private UsuarioDetailsService usuarioDetailsService;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/api/usuarios/registro", "/api/login").permitAll()
                        // El dispatch interno de error no debe quedar detrás de la autenticación: si no,
                        // un 403 o un 500 terminan convertidos en 401 por el authenticationEntryPoint.
                        .requestMatchers("/error").permitAll()
                        .requestMatchers("/api/admin/**").hasAuthority("ADMIN")
                        .requestMatchers("/api/veterinario/**").hasAnyAuthority("VETERINARIO", "ADMIN")
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint((request, response, authException) ->
                                escribirError(response, HttpServletResponse.SC_UNAUTHORIZED, "No autenticado"))
                        // Sin handler propio, Spring Security responde 403 con sendError(), lo que dispara
                        // un dispatch a /error y puede terminar pisado por el entrypoint (401).
                        .accessDeniedHandler((request, response, accessDeniedException) ->
                                escribirError(response, HttpServletResponse.SC_FORBIDDEN, "Acceso denegado"))
                )
                .userDetailsService(usuarioDetailsService)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Escribe una respuesta JSON de error con el status indicado.
     *
     * <p>Usa {@code setStatus} y no {@code sendError} a propósito: {@code sendError} provoca un
     * dispatch interno a {@code /error} que vuelve a pasar por la cadena de seguridad y puede
     * sobrescribir el status original (por ejemplo, convertir un 403 en 401).</p>
     */
    private static void escribirError(HttpServletResponse response, int status, String mensaje) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"error\":\"" + mensaje + "\"}");
    }

    /**
     * Evita que Spring Boot registre el filtro JWT dos veces: como {@code @Component} es un bean
     * {@code Filter} y el contenedor lo agregaría a la cadena de servlets, además de la de seguridad.
     * Aquí solo debe correr dentro de {@code securityFilterChain}.
     */
    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtAuthenticationFilterRegistration(
            JwtAuthenticationFilter filter) {
        FilterRegistrationBean<JwtAuthenticationFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setEnabled(false);
        return registration;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Necesario para la autenticación en AuthController
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
