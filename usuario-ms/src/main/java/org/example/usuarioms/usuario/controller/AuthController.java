package org.example.usuarioms.usuario.controller;

import org.example.usuarioms.usuario.config.JwtProvider;
import org.example.usuarioms.usuario.entity.Usuario;
import org.example.usuarioms.usuario.repository.UsuarioRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UsuarioRepository usuarioRepository;
    private final JwtProvider jwtProvider;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UsuarioRepository usuarioRepository, JwtProvider jwtProvider, PasswordEncoder passwordEncoder) {
        this.usuarioRepository = usuarioRepository;
        this.jwtProvider = jwtProvider;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales) {
        Optional<Usuario> userOpt = usuarioRepository.findByEmail(credenciales.get("email"));
        if (userOpt.isPresent()) {
            Usuario usuario = userOpt.get();
            if (passwordEncoder.matches(credenciales.get("password"), usuario.getPassword())) {
                String token = jwtProvider.createToken(usuario);
                return ResponseEntity.ok(Map.of("token", token));
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Credenciales inválidas");
    }

    @PostMapping("/register")
    public ResponseEntity<Usuario> register(@RequestBody Usuario usuario) {
        usuario.setPassword(passwordEncoder.encode(usuario.getPassword()));
        // Por defecto USER si no se especifica
        if (usuario.getRol() == null) usuario.setRol("USER");
        return ResponseEntity.ok(usuarioRepository.save(usuario));
    }
}