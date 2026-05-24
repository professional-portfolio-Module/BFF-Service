package com.example.bff.controller;
import com.example.bff.service.ProxyService;
import com.example.bff.DTO.ApiResponse;
import com.example.bff.service.RoutingService;
import com.example.bff.utils.FingerprintUtils;
import com.example.bff.utils.RequestUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import com.example.bff.utils.MultipartInputStreamFileResource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.core.io.InputStreamResource;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.io.InputStream;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/BFF/api/proxy")
public class ProxyController {

    public ProxyService proxyService;
    public RoutingService routingService;

    @Autowired
    private RequestUtils requestUtils;

    @Autowired
    private FingerprintUtils fingerprintUtils;

    @org.springframework.beans.factory.annotation.Value("${app.auth.mode:hybrid}")
    private String authMode;

    @Autowired
    public ProxyController(RoutingService routingService, ProxyService proxyService) {
        this.routingService = routingService;
        this.proxyService = proxyService;
    }

    @Autowired
    public static final Logger logger = LoggerFactory.getLogger(ProxyController.class);

    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello World!");
    }

    @PostMapping(value = "/Main/**", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> forwardMultipartToMain(
            @RequestHeader(value = "Authorization", required = true) String token,
            @RequestPart("file") MultipartFile file,
            @RequestParam Map<String, String> formFields,
            HttpServletRequest request) {

        // Initialize HttpHeaders
        HttpHeaders headers = new HttpHeaders();

        // Add Correlation ID to headers
        headers = addCorrelationIdHeader(headers);
        String correlationId = headers.getFirst("X-Correlation-Id");
        logger.info("[ProxyController:forwardMultipartToMain] Token received at bff: {} for Correlation ID: {}", token, correlationId);

        // Extract Authorization header from the request if present
        String authHeader = request.getHeader("Authorization");
        logger.info("[ProxyController:forwardMultipartToMain] Authorization header received: {} for Correlation ID: {}", authHeader, correlationId);

        String requestUri = request.getRequestURI().replace("/BFF/api/proxy/Main", "");
        logger.info("[ProxyController:forwardMultipartToMain] RequestUri: {} for Correlation ID: {}", requestUri, correlationId);

        String backendUrl = routingService.determineBackendUrl(requestUri);
        if (backendUrl == null) {
            logger.error("[ProxyController:forwardMultipartToMain] Service not found for URI: {} with Correlation ID: {}", requestUri, correlationId);
            return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.NOT_FOUND.value(), "Service not found", null));
        }

        // Add Authorization header
        if (authHeader != null && !authHeader.isEmpty()) {
            headers.set("Authorization", authHeader);
        } else {
            logger.error("[ProxyController:forwardMultipartToMain] Authorization header is missing or empty for Correlation ID: {}", correlationId);
            return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.UNAUTHORIZED.value(), "Authorization header is missing", null));
        }

        // Set Content-Type for multipart request
        headers.setContentType(MediaType.MULTIPART_FORM_DATA);

        // Prepare the multipart request body
        MultiValueMap<String, Object> body = new LinkedMultiValueMap<>();
        try {
            // Add the file
            if (file != null && !file.isEmpty()) {
                body.add("file", new MultipartInputStreamFileResource(file.getInputStream(), file.getOriginalFilename()));
                logger.info("[ProxyController:forwardMultipartToMain] Added file: {} for Correlation ID: {}", file.getOriginalFilename(), correlationId);
            } else {
                logger.error("[ProxyController:forwardMultipartToMain] File is missing or empty for Correlation ID: {}", correlationId);
                return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.BAD_REQUEST.value(), "File is missing or empty", null));
            }

            // Add all additional form-data parameters
            for (Map.Entry<String, String> entry : formFields.entrySet()) {
                body.add(entry.getKey(), entry.getValue());
                logger.info("[ProxyController:forwardMultipartToMain] Adding form field: {} = {} for Correlation ID: {}", entry.getKey(), entry.getValue(), correlationId);
            }
        } catch (IOException e) {
            logger.error("[ProxyController:forwardMultipartToMain] Error reading file for Correlation ID: {}. Error: {}", correlationId, e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(), "Error reading file: " + e.getMessage(), null));
        }

        // Forward the request with headers and body separately
        ResponseEntity<?> response = proxyService.forwardMultipartRequest(backendUrl + requestUri, headers, body);
        logger.info("[ProxyController:forwardMultipartToMain] Received response for Correlation ID: {}. Status: {}", correlationId, response.getStatusCode());
        return response;
    }

    @GetMapping("/Main/**")
    public ResponseEntity<?> forwardGetRequest(
            @RequestHeader(value = "Authorization", required = false) String token,
            HttpServletRequest request) {

        HttpHeaders headers = new HttpHeaders();
        headers = addCorrelationIdHeader(headers);
        String correlationId = headers.getFirst("X-Correlation-Id");
        if (token != null && !token.isEmpty()) {
            headers.set(HttpHeaders.AUTHORIZATION, token);
            logger.info("[ProxyController:forwardGetRequest] Authorization header added: {} for Correlation ID: {}", token, correlationId);
        }

        String requestUri = request.getRequestURI().replace("/BFF/api/proxy/Main", "");
        String queryString = request.getQueryString();
        String fullRequestUri = queryString != null ? requestUri + "?" + queryString : requestUri;
        String backendUrl = routingService.determineBackendUrl(requestUri);
        if (backendUrl == null) {
            logger.info("[ProxyController:forwardGetRequest] Service not found for URI: {} for Correlation ID: {}", requestUri,correlationId );
            return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.NOT_FOUND.value(), "Service not found", null));
        }

        if (proxyService.isMainServiceEndpoint(requestUri)) {
            return proxyService.forwardRequestWithToken(backendUrl + fullRequestUri, headers, HttpMethod.GET);
        }
        return proxyService.forwardRequestWithToken(backendUrl + fullRequestUri, headers, HttpMethod.GET);
    }


    @RequestMapping(value = "/AuthForward/**", method = {RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.PATCH})
    public ResponseEntity<?> forwardPostRequest(
            @RequestHeader(value = "Authorization", required = false) String token,
            @RequestBody(required = false) Map<String, Object> requestBody,
            HttpServletRequest request, HttpServletResponse response) {
        HttpMethod httpMethod = HttpMethod.valueOf(request.getMethod());

        HttpHeaders headers = new HttpHeaders();
        headers = addCorrelationIdHeader(headers);
        String correlationId = headers.getFirst("X-Correlation-Id");
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            headers.set(HttpHeaders.AUTHORIZATION, authHeader);
            logger.info("[ProxyController:forwardPostRequest] Authorization header added: {} for Correlation ID: {}", authHeader, correlationId);
        } else {
            logger.info("[ProxyController:forwardPostRequest] No Authorization header for Correlation ID {}",correlationId);
        }

        String requestUri = request.getRequestURI().replace("/BFF/api/proxy/AuthForward", "");
        logger.info("[ProxyController:forwardPostRequest] RequestUri : {} for Correlation ID {} ", requestUri, correlationId);

        String backendUrl = routingService.determineBackendUrl(requestUri);
        if (backendUrl == null) {
            logger.info("[ProxyController:forwardPostRequest] Service not found for URI: {} for Correlation ID: {}", requestUri,correlationId );
            return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.NOT_FOUND.value(), "Service not found", null));
        }
        if (proxyService.isOtpVerification(requestUri)) {
            logger.info("[ProxyController] Handling OTP verification for: {} for Correlation ID: {}",
                    requestUri, correlationId);

            ResponseEntity<?> authResponse = proxyService.forwardRequestWithoutToken(
                    backendUrl + requestUri, httpMethod, headers, requestBody);

            logger.info("[ProxyController:forwardPostRequest] OTP verification response: {} for Correlation ID: {}",
                    authResponse, correlationId);

            if (authResponse.getBody() != null) {
                // Check if response is successful before processing
                if (authResponse.getStatusCode().is2xxSuccessful()) {
                    logger.info("[ProxyController:forwardPostRequest] Processing successful OTP verification response for Correlation ID: {}",
                            correlationId);
                    return processAuthResponse(authResponse.getBody(), response);
                } else {
                    logger.warn("[ProxyController:forwardPostRequest] OTP verification failed with status: {} for Correlation ID: {}",
                            authResponse.getStatusCode(), correlationId);
                }
            } else {
                logger.error("[ProxyController:forwardPostRequest] OTP verification response body is null for Correlation ID: {}",
                        correlationId);
            }
            return authResponse;
        }
        if (proxyService.isAuthEndpoint(requestUri)) {
            logger.info("[ProxyController:forwardPostRequest] Skipping token validation for auth endpoint: {} for Correlation ID: {} ", requestUri, correlationId);
            return proxyService.forwardRequestWithoutToken(backendUrl + requestUri, httpMethod, headers, requestBody);
        }else if (proxyService.isSignup(requestUri)) {
            logger.info("[ProxyController:forwardPostRequest] Skipping token validation for User sign up endpoint: {} for Correlation ID: {} ", requestUri, correlationId);
            ResponseEntity<?> authResponse = proxyService.forwardRequestWithoutToken(backendUrl + requestUri, httpMethod, headers, requestBody);
            logger.info("[ProxyController:forwardPostRequest] authResponse {} for Correlation ID: {} ", authResponse, correlationId);
            if (authResponse.getStatusCode().is2xxSuccessful() && authResponse != null) {
                logger.info("[ProxyController:forwardPostRequest] Process AuthResponse for Correlation ID: {} ", correlationId);
                return processAuthResponse(authResponse.getBody(), response); //To do (need to change for the sign-up)
            }
            return authResponse;
        } else if (proxyService.isLogin(requestUri)) {
            logger.info("[ProxyController:forwardPostRequest] Skipping token validation for logging endpoint: {} for Correlation ID: {} ", requestUri, correlationId);
            ResponseEntity<?> authResponse = proxyService.forwardRequestWithoutToken(backendUrl + requestUri, httpMethod, headers, requestBody);
            logger.info("[ProxyController:forwardPostRequest] authResponse {} for Correlation ID: {} ", authResponse, correlationId);
            if (authResponse.getStatusCode().is2xxSuccessful() && authResponse != null) {
                logger.info("[ProxyController:forwardPostRequest] Process AuthResponse for Correlation ID: {} ", correlationId);
                return processAuthResponse(authResponse.getBody(), response);
            }
            return authResponse;
        } else if (proxyService.isAuthApiEndpoint(requestUri)) {
            logger.info("[ProxyController:forwardPostRequest] Token validation for auth api endpoint for Correlation ID: " + requestUri, correlationId);
            return proxyService.forwardRequestWithToken(backendUrl + requestUri, headers, requestBody, httpMethod);
        } else if (proxyService.isRefreshToken(requestUri)) {
            logger.info("[ProxyController:forwardPostRequest] Token validation for auth endpoint for Correlation ID: " + requestUri, correlationId);

            // Process the logout request (extract and add refresh token to headers)
            boolean requestProcessed = fingerprintUtils.processRefreshTokenRequest(request, headers, correlationId);

            if (!requestProcessed) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponse<>(false, HttpStatus.BAD_REQUEST.value(), "Refresh token is missing or invalid", null));
            }
            return proxyService.forwardRequestWithToken(backendUrl + requestUri, headers, httpMethod );
        } else if (proxyService.isLogout(requestUri)) {
            logger.info("[ProxyController:forwardPostRequest] Handling logout request for URI: {} for Correlation ID: {}",
                    requestUri, correlationId);

            // Process the logout request (extract and add refresh token to headers)
            boolean requestProcessed = fingerprintUtils.processLogoutRequest(request, headers, correlationId);

            if (!requestProcessed) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ApiResponse<>(false, HttpStatus.BAD_REQUEST.value(), "Refresh token is missing or invalid", null));
            }

            // Forward the request to the auth service
            ResponseEntity<?> logoutResponse = proxyService.forwardRequestWithTokenForLogout(
                    backendUrl + requestUri, headers, httpMethod, correlationId);

            // Process the logout response (clear cookies if successful)
            return fingerprintUtils.processLogoutResponse(logoutResponse, response, correlationId);
        } else if (proxyService.isAdminEndpoint(requestUri)) {
            // Admin endpoints - forward without JWT validation (admin key is validated by Auth Service)
            logger.info("[ProxyController:forwardPostRequest] Forwarding admin endpoint without JWT validation: {} for Correlation ID: {}", requestUri, correlationId);
            
            // Copy X-Admin-Key header if present
            String adminKey = request.getHeader("X-Admin-Key");
            if (adminKey != null && !adminKey.isEmpty()) {
                headers.set("X-Admin-Key", adminKey);
            }
            
            return proxyService.forwardRequestWithoutToken(backendUrl + requestUri, httpMethod, headers, requestBody);
        }
        return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.UNAUTHORIZED.value(), "Invalid endpoint", null));
    }
    @GetMapping("/AuthForward/**")
    public ResponseEntity<?> forwardGetRequest(
            @RequestHeader(value = "Authorization", required = false) String token,
            @RequestBody(required = false) Map<String, Object> requestBody,
            HttpServletRequest request, HttpServletResponse response) {

        HttpHeaders headers = new HttpHeaders();
        headers = addCorrelationIdHeader(headers);
        String correlationId = headers.getFirst("X-Correlation-Id");
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            headers.set(HttpHeaders.AUTHORIZATION, authHeader);
            logger.info("[ProxyController:forwardPostRequest] Authorization header added: {} for Correlation ID: {}", authHeader, correlationId);
        } else {
            logger.info("[ProxyController:forwardPostRequest] No Authorization header for Correlation ID {}",correlationId);
        }

        String requestUri = request.getRequestURI().replace("/BFF/api/proxy/AuthForward", "");
        logger.info("[ProxyController:forwardPostRequest] RequestUri : {} for Correlation ID {} ", requestUri, correlationId);

        String backendUrl = routingService.determineBackendUrl(requestUri);
        if (backendUrl == null) {
            logger.info("[ProxyController:forwardPostRequest] Service not found for URI: {} for Correlation ID: {}", requestUri,correlationId );
            return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.NOT_FOUND.value(), "Service not found", null));
        }
        if (proxyService.isAuthApiEndpoint(requestUri)) {
            logger.info("[ProxyController:forwardPostRequest] Token validation for auth endpoint for Correlation ID: " + requestUri, correlationId);

            return proxyService.forwardRequestWithToken(backendUrl + requestUri, headers, HttpMethod.GET );
        }
        return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.UNAUTHORIZED.value(), "Invalid endpoint", null));
    }

    @RequestMapping(value = "/Main/**", method = {RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.PATCH})
    public ResponseEntity<?> MainForwardPostRequest(
            @RequestHeader(value = "Authorization", required = true) String token,
            @RequestBody(required = false) Map<String, Object> requestBody,
            HttpServletRequest request) {
        HttpMethod httpMethod = HttpMethod.valueOf(request.getMethod());

        // Initialize HttpHeaders
        HttpHeaders headers = new HttpHeaders();

        // Add Correlation ID to headers
        headers = addCorrelationIdHeader(headers);
        String correlationId = headers.getFirst("X-Correlation-Id");
        logger.info("[ProxyController:MainForwardPostRequest] Token received at bff: {} for Correlation ID: {} ", token , correlationId);

        // Extract Authorization header from the request if present
        String authHeader = request.getHeader("Authorization");
        logger.info("[ProxyController:MainForwardPostRequest] Authorization header received: " + authHeader);

        String requestUri = request.getRequestURI().replace("/BFF/api/proxy/Main", "");
        logger.info("[ProxyController:MainForwardPostRequest] RequestUri : " + requestUri);

        String backendUrl = routingService.determineBackendUrl(requestUri);
        if (backendUrl == null) {
            logger.info("[ProxyController:MainForwardPostRequest] Service not found for URI: {} for Correlation ID: {}", requestUri,correlationId );
            return ResponseEntity.ok(new ApiResponse<>(false, HttpStatus.NOT_FOUND.value(), "Service not found", null));
        }

        // Add Authorization header
        if (authHeader != null && !authHeader.isEmpty()) {
            headers.set("Authorization", authHeader);
        }

        // Skip token validation for auth endpoints (login/signup)
        if (proxyService.isMainServiceEndpoint(requestUri)) {
            return proxyService.forwardRequestWithToken(backendUrl + requestUri, headers, requestBody, httpMethod);
        }
        return proxyService.forwardRequestWithToken(backendUrl + requestUri, headers, requestBody, httpMethod);
    }

    private HttpHeaders addCorrelationIdHeader(HttpHeaders headers) {
        HttpHeaders updatedHeaders = new HttpHeaders(headers);

        if (!headers.containsKey("X-Correlation-Id")) {
            String correlationId = requestUtils.generateCorrelationId();
            updatedHeaders.add("X-Correlation-Id", correlationId);
            logger.info("[ProxyController:addCorrelationIdHeader] Correlation ID generated: {}", correlationId);  // Log the generated CorrelationId
        }

        return updatedHeaders;
    }

    /**
     * Check if the current request endpoint requires tokens in response (like verify-otp-login)
     * GET OTP endpoints (/auth/sign-in) should NOT have tokens in response
     */
    private boolean isTokenRequiredEndpoint() {
        // This is a simplified check - in production, you might want to pass the URI to this method
        // For now, we'll check the request context or use a flag set earlier
        // Endpoints that should have tokens: verify-otp-login, refresh-token
        // Endpoints that should NOT have tokens: sign-in (get OTP), sign-up
        return true; // Default to true to be safe - tokens are important
    }


    /**
     * Process authentication response:
     * - In 'cookie' mode: Extract tokens and set as cookies, remove from response body
     * - In 'token' mode: Keep tokens in response body, don't set cookies
     * - In 'hybrid' mode: Set cookies AND keep tokens in response body (for mobile + web support)
     */
    private ResponseEntity<?> processAuthResponse(Object responseBody, HttpServletResponse response) {
        try {
            if (responseBody == null) {
                logger.error("[ProxyController:processAuthResponse] Response body is null");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new ApiResponse<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                                "Error processing authentication response: empty response", null));
            }

            // Convert response to string if it's not already
            String responseStr = responseBody instanceof String ?
                    (String) responseBody : responseBody.toString();
            logger.info("[ProxyController:processAuthResponse] Response body: {}", responseStr);
            logger.info("[ProxyController:processAuthResponse] Auth mode: {}", authMode);
            logger.debug("[ProxyController:processAuthResponse] Processing response: {}", responseStr);

            // Parse the JSON string
            ObjectMapper objectMapper = new ObjectMapper();
            JsonNode rootNode = objectMapper.readTree(responseStr);

            // Check if response is successful
            boolean isSuccess = rootNode.has("success") && rootNode.get("success").asBoolean();
            if (!isSuccess) {
                logger.warn("[ProxyController:processAuthResponse] Response indicates failure, returning original response");
                // If not successful, return the original response
                return ResponseEntity.status(HttpStatus.OK).body(responseStr);
            }

            // Check if response has data
            if (!rootNode.has("data")) {
                // For GET OTP endpoint (/auth/sign-in), null data is expected - it just confirms OTP was sent
                // Only warn for endpoints that should return tokens (like verify-otp-login)
                if (isTokenRequiredEndpoint()) {
                    logger.warn("[ProxyController:processAuthResponse] Response has no 'data' field. " +
                            "Auth service may not be returning tokens. This is required for setting cookies.");
                    logger.warn("[ProxyController:processAuthResponse] Response structure: success={}, statusCode={}, message={}",
                            rootNode.has("success") ? rootNode.get("success").asBoolean() : "N/A",
                            rootNode.has("statusCode") ? rootNode.get("statusCode").asInt() : "N/A",
                            rootNode.has("message") ? rootNode.get("message").asText() : "N/A");
                } else {
                    logger.info("[ProxyController:processAuthResponse] Response has no 'data' field (expected for OTP send endpoint)");
                }
                return ResponseEntity.status(HttpStatus.OK).body(responseStr);
            }

            JsonNode dataNode = rootNode.get("data");

            // Check if we have the new nested structure with authData
            JsonNode authDataNode = null;
            if (dataNode.has("authData")) {
                authDataNode = dataNode.get("authData");
                logger.info("[ProxyController:processAuthResponse] Found nested authData structure");
            } else {
                logger.info("[ProxyController:processAuthResponse] Using flat data structure (backward compatibility)");
            }

            // Track what cookies we're setting
            boolean hasFingerprint = false;
            boolean hasRefreshToken = false;
            boolean hasAccessToken = false;
            boolean hasUserName = false;

            // Only set cookies if mode is 'cookie' or 'hybrid'
            boolean shouldSetCookies = "cookie".equalsIgnoreCase(authMode) || "hybrid".equalsIgnoreCase(authMode);

            if (shouldSetCookies) {
                logger.info("[ProxyController:processAuthResponse] Setting cookies (mode: {})", authMode);

                // Extract fingerprint and set as cookie if present
                // Check in authData first, then in data directly for backward compatibility
                if ((authDataNode != null && authDataNode.has("fingerprint")) || dataNode.has("fingerprint")) {
                    String fingerprint = authDataNode != null && authDataNode.has("fingerprint") ?
                            authDataNode.get("fingerprint").asText() : dataNode.get("fingerprint").asText();
                    logger.info("[ProxyController:processAuthResponse] Fingerprint found in auth response");
                    fingerprintUtils.setFingerprintCookie(response, fingerprint);
                    hasFingerprint = true;
                }

                // Extract and set refreshToken as cookie if present
                if ((authDataNode != null && authDataNode.has("refreshToken")) || dataNode.has("refreshToken")) {
                    String refreshToken = authDataNode != null && authDataNode.has("refreshToken") ?
                            authDataNode.get("refreshToken").asText() : dataNode.get("refreshToken").asText();
                    logger.info("[ProxyController:processAuthResponse] RefreshToken found in auth response");
                    fingerprintUtils.setRefreshTokenCookie(response, refreshToken);
                    hasRefreshToken = true;
                }

                // Extract and set access_token as cookie if present
                if ((authDataNode != null && authDataNode.has("access_token")) || dataNode.has("access_token")) {
                    String accessToken = authDataNode != null && authDataNode.has("access_token") ?
                            authDataNode.get("access_token").asText() : dataNode.get("access_token").asText();
                    logger.info("[ProxyController:processAuthResponse] AccessToken found in auth response");
                    fingerprintUtils.setAccessTokenCookie(response, accessToken);
                    hasAccessToken = true;
                }

                // Extract and set user_name as cookie if present
                if ((authDataNode != null && authDataNode.has("user_name")) || dataNode.has("user_name")) {
                    String userName = authDataNode != null && authDataNode.has("user_name") ?
                            authDataNode.get("user_name").asText() : dataNode.get("user_name").asText();
                    logger.info("[ProxyController:processAuthResponse] UserName found in auth response");
                    fingerprintUtils.setUserNameCookie(response, userName);
                    hasUserName = true;
                }

                // Extract and set user_role as cookie if present
                if ((authDataNode != null && authDataNode.has("user_role")) || dataNode.has("user_role")) {
                    String userRole = authDataNode != null && authDataNode.has("user_role") ?
                            authDataNode.get("user_role").asText() : dataNode.get("user_role").asText();
                    logger.info("[ProxyController:processAuthResponse] UserRole found in auth response");
                    fingerprintUtils.setRoleCookie(response, userRole);
                }

                // Extract and set user_role_Id as cookie if present
                if ((authDataNode != null && authDataNode.has("user_role_Id")) || dataNode.has("user_role_Id")) {
                    Long userRoleId = authDataNode != null && authDataNode.has("user_role_Id") ?
                            authDataNode.get("user_role_Id").asLong() : dataNode.get("user_role_Id").asLong();
                    logger.info("[ProxyController:processAuthResponse] UserRole Id found in auth response");
                    fingerprintUtils.setRoleIDCookie(response, userRoleId);
                }

                // Extract and set work_flow_role_Id as cookie if present
                if ((authDataNode != null && authDataNode.has("work_flow_role_Id")) || dataNode.has("work_flow_role_Id")) {
                    Long workFlowRoleId = authDataNode != null && authDataNode.has("work_flow_role_Id") ?
                            authDataNode.get("work_flow_role_Id").asLong() : dataNode.get("work_flow_role_Id").asLong();
                    logger.info("[ProxyController:processAuthResponse] workFlowRoleId Id found in auth response");
                    fingerprintUtils.setWorkFlowRoleIDCookie(response, workFlowRoleId);
                }

                // Log warning if essential tokens are missing
                if (!hasAccessToken || !hasRefreshToken) {
                    logger.error("[ProxyController:processAuthResponse] CRITICAL: Auth response is missing essential tokens! " +
                            "AccessToken: {}, RefreshToken: {}, Fingerprint: {}, UserName: {}",
                            hasAccessToken, hasRefreshToken, hasFingerprint, hasUserName);
                    logger.error("[ProxyController:processAuthResponse] This will cause authentication to fail. " +
                            "The auth service MUST return tokens in the response body for successful authentication.");
                } else {
                    logger.info("[ProxyController:processAuthResponse] Successfully extracted and set cookies: " +
                            "AccessToken: {}, RefreshToken: {}, Fingerprint: {}, UserName: {}",
                            hasAccessToken, hasRefreshToken, hasFingerprint, hasUserName);
                }
            } else {
                logger.info("[ProxyController:processAuthResponse] Skipping cookie setting (mode: {})", authMode);
            }

            // Decide whether to remove sensitive data from response body
            // In 'cookie' mode: remove tokens from response body (security)
            // In 'token' or 'hybrid' mode: keep tokens in response body (for mobile apps)
            boolean shouldKeepTokensInBody = "token".equalsIgnoreCase(authMode) || "hybrid".equalsIgnoreCase(authMode);

            if (shouldKeepTokensInBody) {
                logger.info("[ProxyController:processAuthResponse] Keeping tokens in response body for mobile apps (mode: {})", authMode);
                // Return original response with tokens included
                return ResponseEntity.status(HttpStatus.OK)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(responseStr);
            } else {
                // Create a copy of the data node without sensitive information
                ObjectNode cleanedDataNode = objectMapper.createObjectNode();

                // Copy all fields from data node except fingerprint
                dataNode.fields().forEachRemaining(entry -> {
                    if (!entry.getKey().equals("fingerprint")) {
                        // If this is the authData field, we need to clean it too
                        if (entry.getKey().equals("authData")) {
                            ObjectNode cleanedAuthDataNode = objectMapper.createObjectNode();
                            entry.getValue().fields().forEachRemaining(authEntry -> {
                                if (!authEntry.getKey().equals("fingerprint") &&
                                        !authEntry.getKey().equals("refreshToken") &&
                                        !authEntry.getKey().equals("access_token") &&
                                        !authEntry.getKey().equals("access_token_expiry") &&
                                        !authEntry.getKey().equals("token_type")) {
                                    cleanedAuthDataNode.set(authEntry.getKey(), authEntry.getValue());
                                }
                            });
                            cleanedDataNode.set("authData", cleanedAuthDataNode);
                        } else {
                            cleanedDataNode.set(entry.getKey(), entry.getValue());
                        }
                    }
                });

                // Create a new response with the cleaned data
                ObjectNode cleanedRootNode = objectMapper.createObjectNode();
                cleanedRootNode.put("success", rootNode.get("success").asBoolean());
                cleanedRootNode.put("statusCode", rootNode.get("statusCode").asInt());
                cleanedRootNode.put("message", rootNode.get("message").asText());
                cleanedRootNode.set("data", cleanedDataNode);

                String cleanedResponse = objectMapper.writeValueAsString(cleanedRootNode);
                logger.info("[ProxyController:processAuthResponse] Sensitive data set as cookies and removed from response body (mode: {})", authMode);

                return ResponseEntity.status(HttpStatus.OK)
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(cleanedResponse);
            }
        } catch (Exception e) {
            logger.error("[ProxyController:processAuthResponse] Error processing auth response", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(),
                            "Error processing authentication response: " + e.getMessage(), null));
        }
    }

}
