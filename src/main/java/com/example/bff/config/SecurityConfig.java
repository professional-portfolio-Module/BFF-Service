package com.example.bff.config;

import com.example.bff.controller.ProxyController;
import com.example.bff.security.TokenDecryptionFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.security.interfaces.RSAPublicKey;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final CorsProperties corsProperties;
    private final RSAKeyRecord rsaKeyRecord;

    @Autowired
    private TokenDecryptionFilter tokenDecryptionFilter;

    @Autowired
    public static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    public SecurityConfig(CorsProperties corsProperties, RSAKeyRecord rsaKeyRecord,TokenDecryptionFilter tokenDecryptionFilter) {
        this.corsProperties = corsProperties;
        this.rsaKeyRecord = rsaKeyRecord;
        this.tokenDecryptionFilter= tokenDecryptionFilter;
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // JWT authentication converter for roles
    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        logger.info("JwtAuthenticationConverter started");
        JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        grantedAuthoritiesConverter.setAuthorityPrefix("ROLE_"); // Add "ROLE_" prefix
        grantedAuthoritiesConverter.setAuthoritiesClaimName("roles"); // Define claim for roles

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
        return jwtAuthenticationConverter;
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        RSAPublicKey publicKey = rsaKeyRecord.rsaPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        logger.info("Configuring SecurityFilterChain...");

        http
                .csrf(csrf -> csrf.disable()) // Disable because of stateless JWT authentication
                .authorizeHttpRequests(auth -> auth
                        // WebSocket endpoints - authentication handled by WebSocket handler
                        .requestMatchers("/vx/flutter").permitAll()
                        .requestMatchers("/vx/gateway", "/vx/gateway/**", "/vx/gateway/deviceDiscovery").permitAll()
                        .requestMatchers("/vx/device-assignment").permitAll()  // Device assignment WebSocket endpoint
                        // Internal service-to-service communication endpoints (no JWT required)
                        .requestMatchers("/BFF/api/device-assignment/**").permitAll()  // Device assignment API for Main Service -> WebSocket Service
                        .requestMatchers("/BFF/api/proxy/AuthForward/auth/api/**").authenticated()
                        .requestMatchers("/BFF/api/proxy/AuthForward/**").permitAll()
                        .requestMatchers("/BFF/api/proxy/auth/session/**").authenticated()
                        .requestMatchers("/BFF/api/proxy/Main/**").authenticated()
                        .requestMatchers("/latest/**").denyAll()
                        .anyRequest().denyAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                )
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // Add this part to prevent Clickjacking
                .headers(headers -> headers
                        .frameOptions(frameOptions -> frameOptions.deny())
                        .contentSecurityPolicy(csp -> csp
                                .policyDirectives("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';"))
                        .httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .preload(true)
                                .maxAgeInSeconds(31536000))
                )
                // Add custom filter before Spring Security processes JWT authentication
                .addFilterBefore(tokenDecryptionFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


    // CORS configuration
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(corsProperties.getAllowedOrigins());
        configuration.setAllowedMethods(List.of("GET", "POST")); // Define allowed HTTP methods
        configuration.setAllowedHeaders(List.of("*")); // Allow all headers
        configuration.setAllowCredentials(true); // Allow credentials

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}
