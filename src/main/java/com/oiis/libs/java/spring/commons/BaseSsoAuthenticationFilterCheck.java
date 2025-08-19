package com.oiis.libs.java.spring.commons;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class BaseSsoAuthenticationFilterCheck extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(BaseSsoAuthenticationFilterCheck.class);

    @Value("${app.security.public-endpoints}")
    private List<String> publicEndpoints;

    @Value("${sso.base-endpoint}")
    String baseSsoEndpoint;

    @Value("${sso.check-token-endpoint}")
    private String checkTokenEndPoint;

    private WebClient webClient;

    @Autowired
    private ObjectMapper objectMapper;


    public BaseSsoAuthenticationFilterCheck(String baseSsoEndpoint) {
        this.webClient = WebClient.create(baseSsoEndpoint);
    }

    private void writeBodyResponse(DefaultDataSwap bodyResponse, String message, HttpServletResponse response) {
        try {
            bodyResponse.message = message;
            logger.debug(bodyResponse.message);
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            if (bodyResponse.exception != null) {
                bodyResponse.exception.printStackTrace();
            }
            bodyResponse.exception = null;
            response.getWriter().write(objectMapper.writeValueAsString(bodyResponse));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Protect end points of not authorized access (midleware) and call sso ot check token
     * @param request
     * @param response
     * @param filterChain
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        logger.debug("INIT {}.{}", this.getClass().getSimpleName(), "doFilterInternal");
        DefaultDataSwap bodyResponse = new DefaultDataSwap();
        try {
            String path = request.getRequestURI();
            logger.debug("endpoint: {}",path);

            if (publicEndpoints.contains(path)) {
                logger.debug("endpoint is public");
                filterChain.doFilter(request, response);
                return;
            }
            logger.debug("endpoint is not public, checking token in Authorization header");

            String authHeader = request.getHeader("Authorization");
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                writeBodyResponse(bodyResponse,"missing or invalid token",response);
                return;
            }

            String token = authHeader.substring(7);
            logger.debug("token: {}", token);
            if (StringUtils.hasText(token)) {
                ResponseEntity<DefaultDataSwap> responseEntity = webClient.post()
                        .uri(checkTokenEndPoint)
                        .accept(MediaType.APPLICATION_JSON)
                        .contentType(MediaType.APPLICATION_JSON)
                        .bodyValue("{\"token\":\""+token+"\"}")
                        //.retrieve();
                        .exchangeToMono(requestResponse ->
                                requestResponse.bodyToMono(DefaultDataSwap.class)
                                        .map(body -> ResponseEntity.status(requestResponse.statusCode()).body(body))
                        )
                        .block();

                if (responseEntity != null) {
                    org.springframework.http.HttpStatusCode statusCode = responseEntity.getStatusCode();
                    bodyResponse = responseEntity.getBody();
                    Map<String, Object> dataNode = null;
                    if (bodyResponse != null) {
                        dataNode = (Map<String, Object>) bodyResponse.data;
                    }
                    logger.debug("status code {}",statusCode);
                    if (statusCode.is2xxSuccessful()) {
                        if (dataNode != null && dataNode.containsKey("token") && dataNode.containsKey("user_id")) {
                            String ssoToken = String.valueOf(dataNode.get("token"));
                            String userId = String.valueOf(dataNode.get("user_id"));
                            if (StringUtils.hasText(ssoToken) && StringUtils.hasText(userId)) {
                                UsernamePasswordAuthenticationToken authentication =
                                        new UsernamePasswordAuthenticationToken(dataNode, null, List.of());
                                SecurityContextHolder.getContext().setAuthentication(authentication);
                            } else {
                                writeBodyResponse(bodyResponse,"missing body data token on sso response",response);
                                return;
                            }
                        } else {
                            writeBodyResponse(bodyResponse,"missing body data on sso response",response);
                            return;
                        }
                    } else {
                        response.setStatus(statusCode.value());
                        writeBodyResponse(bodyResponse, Objects.requireNonNullElse(responseEntity.getBody().message, "not authenticated by sso"),response);
                        return;
                    }
                }
            } else {
                writeBodyResponse(bodyResponse,"missing or invalid token",response);
                return;
            }

            filterChain.doFilter(request, response);
        } catch (Exception e) {
            e.printStackTrace();
            writeBodyResponse(bodyResponse,e.getMessage(),response);
            return;
        }
        logger.debug("END {}.{}", this.getClass().getSimpleName(), "doFilterInternal");
    }


}
