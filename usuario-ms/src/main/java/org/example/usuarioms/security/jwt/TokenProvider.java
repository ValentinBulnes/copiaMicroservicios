package org.example.usuarioms.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import org.example.usuarioms.usuario.entity.Usuario; // Tu entidad Usuario

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class TokenProvider {

    // CLAVE SECRETA (Debe ser la misma en el Gateway)
    private static final String SECRET = "j7ZookpUTYxclaULynjypGQVKMYXqOXMI+/1sQ2gOV1BF6VOHw6OzYj9RNZY4GcHAE3Igrah3MZ26oLrY/3y4Q==";

    private final SecretKey key;
    private final int tokenValidityInMilliseconds = 1000 * 60 * 60 * 10; // 10 horas

    public TokenProvider() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    // Modificado para recibir tu entidad Usuario
    public String createToken(Usuario usuario) {
        Map<String, Object> claims = new HashMap<>();
        // Asumimos que tu Usuario tiene un campo String rol o similar
        claims.put("rol", usuario.getRol());
        claims.put("id", usuario.getId());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(usuario.getEmail()) // Usamos email como identificador
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + tokenValidityInMilliseconds))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // El resto de métodos de validación no son estrictamente necesarios aquí
    // porque quien valida es el Gateway, pero puedes dejarlos.
}