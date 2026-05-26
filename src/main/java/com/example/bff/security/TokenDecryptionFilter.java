package com.example.bff.security;

import com.example.bff.service.JwtService;
import com.example.bff.service.ProxyService;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

@Component
public class TokenDecryptionFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(TokenDecryptionFilter.class);

    @Autowired
    private JwtService jwtService;

    @Autowired
    private Environment environment;

    @Autowired
    private ProxyService proxyService;

    private boolean fingerprintVerificationEnabled;

    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    // Flag to track if a token has been processed
    private static final String DECRYPTION_PROCESSED_ATTRIBUTE = "TOKEN_DECRYPTION_PROCESSED";

    @Autowired
    public TokenDecryptionFilter(JwtService jwtService, Environment environment) {
        this.jwtService = jwtService;
        this.environment = environment;
    }

    @PostConstruct
    public void init() {
        fingerprintVerificationEnabled = Boolean.parseBoolean(environment.getProperty("fingerprint.verification.enabled", "false"));
        logger.info("[TokenDecryptionFilter:init] Fingerprint verification enabled: {}", fingerprintVerificationEnabled);
    }

    public TokenDecryptionFilter() {
    }

    private boolean isPathExcluded(String requestURI) {
        if (environment == null) {
            return false;
        }
        String excludedPathsStr = environment.getProperty("app.fingerprint.verification.excluded-paths", "");
        if (excludedPathsStr.isEmpty()) {
            return false;
        }
        String[] paths = excludedPathsStr.split(",");
        for (String path : paths) {
            if (pathMatcher.match(path.trim(), requestURI)) {
                return true;
            }
        }
        return false;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        logger.info("[TokenDecryptionFilter:doFilterInternal] Started for URI: {}", request.getRequestURI());

        // Mark this request as processed to prevent multiple applications of this filter
        request.setAttribute(DECRYPTION_PROCESSED_ATTRIBUTE, Boolean.TRUE);

        logger.info("[TokenDecryptionFilter:doFilterInternal] fingerprintVerificationEnabled={}", fingerprintVerificationEnabled);
        
        // Skip token processing for public auth endpoints or excluded paths
        String requestURI = request.getRequestURI();
        if (requestURI.contains("/auth/sign-in") || requestURI.contains("/auth/sign-up") || 
            requestURI.contains("/auth/refresh-token") || requestURI.contains("/BFF/api/health") ||
            isPathExcluded(requestURI)) {
            logger.info("[TokenDecryptionFilter:doFilterInternal] Public or excluded endpoint: {}, skipping token processing", requestURI);
            chain.doFilter(request, response);
            return;
        }

        String requestUri = request.getRequestURI().replace("/BFF/api/proxy/AuthForward", "");
        String accessTokenCookieName = jwtService.getAccessTokenCookieName();
        String refreshTokenCookieName = jwtService.getRefreshTokenCookieName();
        String token = null;
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (accessTokenCookieName.equals(cookie.getName())) {
                    token = cookie.getValue();
                    logger.info("[TokenDecryptionFilter:doFilterInternal] Access token found in cookie");
                    break;
                }
            }

            // If access token was not found, try refresh token
            if (token == null && proxyService.isRefreshToken(requestUri)) {
                for (Cookie cookie : request.getCookies()) {
                    if (refreshTokenCookieName.equals(cookie.getName())) {
                        token = cookie.getValue();
                        logger.info("[TokenDecryptionFilter:doFilterInternal] Refresh token found in cookie");
                        break;
                    }
                }
            }
        }

        // Fallback: If no token found in cookies, try Authorization header
        if (token == null) {
            String authHeader = request.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                token = authHeader.substring(7);
                logger.info("[TokenDecryptionFilter:doFilterInternal] Token found in Authorization header");
            }
        }

        if (token == null) {
            chain.doFilter(request, response);
            return;
        }

        // Check if the token is already in JWT format (contains two dots)
        boolean isJwtFormat = token.contains(".") && token.split("\\.").length == 3;

        if (!isJwtFormat) {
            try {
                // Only decrypt if the token is not already in JWT format
                String decryptedToken = TokenDecryptionUtil.decryptToken(token);
                logger.info("[TokenDecryptionFilter:doFilterInternal] Token decrypted successfully");

                // Verify fingerprint if enabled
                if (fingerprintVerificationEnabled) {
                    String fingerprintCookieName = jwtService.getFingerprintCookieName();
                    String cookieFingerprint = null;

                    if (request.getCookies() != null) {
                        for (Cookie cookie : request.getCookies()) {
                            if (fingerprintCookieName.equals(cookie.getName())) {
                                cookieFingerprint = cookie.getValue();
                                break;
                            }
                        }
                    }

                    if (cookieFingerprint == null) {
                        logger.error("[TokenDecryptionFilter:doFilterInternal] Fingerprint cookie not found");
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.getWriter().write("{\"error\":\"Fingerprint cookie missing. Possible token theft!\"}");
                        return;
                    }

                    // Get fingerprint from token
                    String tokenFingerprint = jwtService.getTokenFingerprint(decryptedToken);

                    if (tokenFingerprint == null) {
                        logger.error("[TokenDecryptionFilter:doFilterInternal] Fingerprint claim not found in token");
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.getWriter().write("{\"error\":\"Fingerprint claim missing from token\"}");
                        return;
                    }

                    // Compare fingerprints
                    if (!tokenFingerprint.equals(cookieFingerprint)) {
                        logger.error("[TokenDecryptionFilter:doFilterInternal] Fingerprint mismatch - possible token theft");
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.getWriter().write("{\"error\":\"Fingerprint mismatch. Possible token theft!\"}");
                        return;
                    }

                    logger.info("[TokenDecryptionFilter:doFilterInternal] Fingerprint verification successful");
                }

                // Replace encrypted token with decrypted token
                request = new DecipheredTokenRequestWrapper(request, decryptedToken);
                logger.info("[TokenDecryptionFilter:doFilterInternal] Modified request Authorization header");
            } catch (Exception e) {
                logger.error("[TokenDecryptionFilter:doFilterInternal] Token decryption failed: {}", e.getMessage());
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.getWriter().write("{\"error\":\"Invalid token\"}");
                return;
            }
        } else {
            logger.info("[TokenDecryptionFilter:doFilterInternal] Token is already in JWT format, skipping decryption");

            // If fingerprint verification is enabled, still verify the fingerprint
            if (fingerprintVerificationEnabled) {
                try {
                    // Get fingerprint from cookie
                    String fingerprintCookieName = jwtService.getFingerprintCookieName();
                    logger.debug("[TokenDecryptionFilter:doFilterInternal] fingerprintCookieName: {}", fingerprintCookieName);
                    String cookieFingerprint = null;

                    if (request.getCookies() != null) {
                        for (Cookie cookie : request.getCookies()) {
                            if (fingerprintCookieName.equals(cookie.getName())) {
                                cookieFingerprint = cookie.getValue();
                                logger.debug("[TokenDecryptionFilter:doFilterInternal] Fingerprint cookie: {}", cookieFingerprint);
                                break;
                            }
                        }
                    }

                    if (cookieFingerprint == null) {
                        logger.error("[TokenDecryptionFilter:doFilterInternal] Fingerprint cookie not found");
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.getWriter().write("{\"error\":\"Fingerprint cookie missing. Possible token theft!\"}");
                        return;
                    }

                    // Get fingerprint from token
                    String tokenFingerprint = jwtService.getTokenFingerprint(token);
                    logger.debug("[TokenDecryptionFilter:doFilterInternal] tokenFingerprint: {}", tokenFingerprint);
                    if (tokenFingerprint == null) {
                        logger.error("[TokenDecryptionFilter:doFilterInternal] Fingerprint claim not found in token");
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.getWriter().write("{\"error\":\"Fingerprint claim missing from token\"}");
                        return;
                    }

                    // Compare fingerprints
                    if (!tokenFingerprint.equals(cookieFingerprint)) {
                        logger.error("[TokenDecryptionFilter:doFilterInternal] Fingerprint mismatch - possible token theft");
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                        response.getWriter().write("{\"error\":\"Fingerprint mismatch. Possible token theft!\"}");
                        return;
                    }

                    logger.info("[TokenDecryptionFilter:doFilterInternal] Fingerprint verification successful for JWT token");
                } catch (Exception e) {
                    logger.error("[TokenDecryptionFilter:doFilterInternal] Fingerprint verification failed: {}", e.getMessage());
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.getWriter().write("{\"error\":\"Fingerprint verification failed\"}");
                    return;
                }
            }
        }

        // Continue the filter chain
        chain.doFilter(request, response);
    }
}
