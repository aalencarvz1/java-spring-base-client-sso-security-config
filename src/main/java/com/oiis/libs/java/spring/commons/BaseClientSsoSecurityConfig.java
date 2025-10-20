package com.oiis.libs.java.spring.commons;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;


/**
 * Class that represents base sso client configuration.
 *
 * @author aalvencarvz1
 * @version 1.0.0
 */
@Configuration
@EnableWebSecurity
public class BaseClientSsoSecurityConfig {

    private static final Logger logger = LoggerFactory.getLogger(BaseClientSsoSecurityConfig.class);

    /**
     * default filter check
     *
     * @param baseSsoEndpoint the endpoint of sso
     * @return instance of this base filter check
     */
    @Bean
    public BaseSsoAuthenticationFilterCheck baseSsoAuthenticationFilterCheck(@Value("${sso.base-endpoint}") String baseSsoEndpoint) {
        return new BaseSsoAuthenticationFilterCheck(baseSsoEndpoint);
    }

    @Value("${app.security.public-endpoints}")
    private List<String> publicEndpoints;

    /**
     * Configure cors
     *
     * @return the cors configuration
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.addAllowedOrigin("*"); // ou coloque a origem específica do seu front
        configuration.addAllowedMethod("*");
        configuration.addAllowedHeader("*");
        configuration.setAllowCredentials(false); // ou true, se usar cookies/sessão

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }

    /**
     * filter chain
     *
     * @param http the http security request
     * @param baseSsoAuthenticationFilterCheck the base client filter check
     * @return the security filter chain
     * @throws Exception throw exception if error on http build
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, BaseSsoAuthenticationFilterCheck baseSsoAuthenticationFilterCheck) throws Exception {
        logger.debug("public endpoints: {} {}", Arrays.toString(publicEndpoints.toArray(new String[0])),publicEndpoints);
        http.csrf(csrf -> csrf.disable()) // desabilita CSRF no novo padrão
                .cors(Customizer.withDefaults())             // habilita CORS (pode customizar aqui)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(publicEndpoints.toArray(new String[0]))
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .addFilterBefore(baseSsoAuthenticationFilterCheck, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class);
        ;
        return http.build();
    }
}