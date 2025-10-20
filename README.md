# Base Client SSO Security Configuration

This library provides a Spring Security configuration for integrating Single Sign-On (SSO) authentication into your Spring Boot application. It includes a base security configuration and a filter to validate JWT tokens against an SSO server, ensuring secure access to protected endpoints.

DEPRECATED - 2025-10-20 - This class is deprecated, use com.oiis.libs.security.sso.base_server_sso_client_security_config.BaseServerSSOClientSecurityConfig in replacement this.

## Features
- Configures Spring Security with a custom SSO authentication filter.
- Supports public endpoints that bypass authentication.
- Validates JWT tokens via an external SSO server.
- Configurable CORS settings for cross-origin requests.
- Disables CSRF protection for stateless API usage.

## Prerequisites
- Spring Boot 3.x
- Java 17 or higher
- An SSO server providing token validation endpoints
- Maven or Gradle for dependency management

## Installation

Add the following dependency to your `pom.xml` (Maven) or `build.gradle` (Gradle):

### Maven
```xml
<dependency>
    <groupId>com.oiis.libs.java.spring.commons</groupId>
    <artifactId>base-security-client-sso-config</artifactId>
    <version>1.0.6</version>
</dependency>
```

### Gradle
```groovy
implementation 'com.oiis.libs.java.spring.commons:base-security-client-sso-config:1.0.6'
```

## Configuration

To use this library, extend the `BaseClientSsoSecurityConfig` class in your Spring Security configuration. Below is an example:

```java
import com.oiis.libs.java.spring.commons.security.BaseClientSsoSecurityConfig;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends BaseClientSsoSecurityConfig {
}
```

### Required Configuration Properties

You need to configure the following properties in your `application.yml` or `application.properties` file:

#### application.yml
```yaml
sso:
  base-endpoint: "http://your-sso-server.com"  # Base URL of the SSO server
  check-token-endpoint: "/api/check-token"     # Endpoint for token validation
app:
  security:
    public-endpoints:                         # List of public endpoints that don't require authentication
      - "/public/**"
      - "/health"
      - "/info"
```

#### application.properties
```properties
sso.base-endpoint=http://your-sso-server.com
sso.check-token-endpoint=/api/check-token
app.security.public-endpoints=/public/**,/health,/info
```

#### Property Descriptions
- **`sso.base-endpoint`**: The base URL of the SSO server (e.g., `http://your-sso-server.com`). This is used to initialize the `WebClient` for token validation.
- **`sso.check-token-endpoint`**: The specific endpoint on the SSO server to validate JWT tokens (e.g., `/api/check-token`).
- **`app.security.public-endpoints`**: A comma-separated list (in `application.properties`) or a YAML list (in `application.yml`) of endpoints that do not require authentication. These endpoints are accessible without a valid JWT token.

### CORS Configuration
The library includes a default CORS configuration that allows all origins, methods, and headers with credentials disabled. You can customize this by overriding the `corsConfigurationSource` bean in your `SecurityConfig` class if needed.

Example customization:
```java
@Bean
public CorsConfigurationSource corsConfigurationSource() {
    CorsConfiguration configuration = new CorsConfiguration();
    configuration.addAllowedOrigin("https://your-frontend.com");
    configuration.addAllowedMethod("GET");
    configuration.addAllowedMethod("POST");
    configuration.addAllowedHeader("Authorization");
    configuration.setAllowCredentials(true);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", configuration);
    return source;
}
```

## How It Works
1. **Security Filter Chain**: The `BaseClientSsoSecurityConfig` class configures a Spring Security filter chain that:
    - Disables CSRF (suitable for stateless APIs).
    - Enables CORS with the provided configuration.
    - Allows unauthenticated access to public endpoints specified in `app.security.public-endpoints`.
    - Requires authentication for all other endpoints using a JWT token.

2. **SSO Authentication Filter**: The `BaseSsoAuthenticationFilterCheck` filter:
    - Checks if the requested endpoint is public. If it is, the request proceeds without authentication.
    - For non-public endpoints, extracts the JWT token from the `Authorization` header (expected format: `Bearer <token>`).
    - Sends the token to the SSO server's `check-token-endpoint` for validation.
    - If the token is valid, sets up Spring Security's authentication context with the user details.
    - If the token is invalid or missing, returns a `401 Unauthorized` response with an error message.

3. **Token Validation**: The filter expects the SSO server to return a JSON response with at least `token` and `user_id` fields in the `data` object. If these fields are present and valid, the user is authenticated; otherwise, the request is rejected.

## Example Request
To access a protected endpoint, include the JWT token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer <your-jwt-token>" http://your-app.com/api/protected
```

For public endpoints (e.g., `/health`), no token is required:

```bash
curl http://your-app.com/health
```

## Logging
The library uses SLF4J for logging. Key events (e.g., token validation, endpoint access) are logged at the `DEBUG` level. Ensure your application's logging configuration is set up to capture these logs if needed.

## Troubleshooting
- **401 Unauthorized**: Ensure the `Authorization` header contains a valid `Bearer <token>`. Verify that the SSO server is reachable and the `sso.check-token-endpoint` is correct.
- **CORS Issues**: Check the `corsConfigurationSource` bean configuration and ensure the frontend origin is allowed if you have customized CORS.
- **Missing Properties**: Ensure all required properties (`sso.base-endpoint`, `sso.check-token-endpoint`, `app.security.public-endpoints`) are defined in your configuration file.

## Contributing
For issues, feature requests, or contributions, please contact the library maintainers or submit a pull request to the repository.

## License
This library is licensed under the MIT License. See the `LICENSE` file for details.