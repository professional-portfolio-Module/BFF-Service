package com.example.bff.controller;

import com.example.bff.DTO.ApiResponse;
import com.example.bff.logger.LoggerAdapter;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/BFF/api/proxy")
public class AuthSessionController {

    @Autowired
    LoggerAdapter logger;

    @GetMapping("/auth/session")
    public ResponseEntity<ApiResponse<?>> getSession(HttpServletRequest request) {
        logger.info("Attempting to retrieve session from cookies or JWT token...");

        try {
            String accessToken = null;
            String userName = null;
            Long userRoleId = null;
            Long workFlowRoleId = null;

            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    switch (cookie.getName()) {
                        case "AccessToken", "__Secure-AccessToken" -> accessToken = cookie.getValue();
                        case "UserName", "__Secure-UserName" -> userName = cookie.getValue();
                        case "RoleId", "__Secure-RoleId" -> {
                            try {
                                userRoleId = Long.parseLong(cookie.getValue());
                            } catch (NumberFormatException e) {
                                logger.warn("Failed to parse RoleId cookie value to Long: " + cookie.getValue());
                            }
                        }
                        case "workFlowRoleId", "__Secure-workFlowRoleId" -> {
                            try {
                                workFlowRoleId = Long.parseLong(cookie.getValue());
                            } catch (NumberFormatException e) {
                                logger.warn("Failed to parse workFlowRoleId cookie value to Long: " + cookie.getValue());
                            }
                        }
                    }
                }
            }

            // Fallback: If no cookies or missing accessToken, extract from SecurityContext (JWT token)
            if (accessToken == null) {
                logger.info("No access token cookie found, checking JWT token from SecurityContext...");
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
                    Jwt jwt = (Jwt) authentication.getPrincipal();
                    userName = jwt.getSubject();
                    
                    Object roleIdObj = jwt.getClaim("roleId");
                    if (roleIdObj == null) {
                        roleIdObj = jwt.getClaim("user_role_Id");
                    }
                    if (roleIdObj instanceof Number) {
                        userRoleId = ((Number) roleIdObj).longValue();
                    } else if (roleIdObj instanceof String) {
                        try {
                            userRoleId = Long.parseLong((String) roleIdObj);
                        } catch (NumberFormatException e) {
                            // ignore
                        }
                    }
                    
                    Object workFlowObj = jwt.getClaim("workFlowRoleId");
                    if (workFlowObj == null) {
                        workFlowObj = jwt.getClaim("work_flow_role_Id");
                    }
                    if (workFlowObj instanceof Number) {
                        workFlowRoleId = ((Number) workFlowObj).longValue();
                    } else if (workFlowObj instanceof String) {
                        try {
                            workFlowRoleId = Long.parseLong((String) workFlowObj);
                        } catch (NumberFormatException e) {
                            // ignore
                        }
                    }
                    
                    accessToken = jwt.getTokenValue();
                    logger.info("Retrieved session details from JWT for user: " + userName + ", roleId: " + userRoleId + ", workFlowRoleId: " + workFlowRoleId);
                }
            }

            if (accessToken == null) {
                logger.warn("Access token missing from both cookies and Authorization header.");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(new ApiResponse<>(false, HttpStatus.UNAUTHORIZED.value(), "Access token missing", null));
            }

            Map<String, Object> user = new HashMap<>();
            user.put("user_name", userName);
            user.put("user_role_Id", userRoleId != null ? userRoleId : 1L);
            user.put("work_flow_role_Id", workFlowRoleId != null ? workFlowRoleId : 1L);

            logger.info("Session retrieved successfully for user: " + userName);
            return ResponseEntity.ok(new ApiResponse<>(true, HttpStatus.OK.value(), "Session found", user));

        } catch (Exception ex) {
            logger.error("Error retrieving session: " + ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ApiResponse<>(false, HttpStatus.INTERNAL_SERVER_ERROR.value(), "Internal server error", null));
        }
    }
}
