package pro.akosarev.sandbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.function.Function;

public class JwtAuthenticationConfigurer
        extends AbstractHttpConfigurer<JwtAuthenticationConfigurer, HttpSecurity> {

    private Function<Token, String> refreshTokenStringSerializer = Object::toString;

    private Function<Token, String> accessTokenStringSerializer = Object::toString;

    private ObjectMapper objectMapper;

    private Function<String, Token> accessTokenStringDeserializer;

    private Function<String, Token> refreshTokenStringDeserializer;

    private JdbcTemplate jdbcTemplate;

    private UserDetailsService daoUserDetailsService;

    private String defaultUsernameJsonBodyParameter = "username";

    private String defaultPasswordJsonBodyParameter = "password";

    private String nativeAppHeader;

    @Override
    public void init(HttpSecurity builder) {
        var csrfConfigurer = builder.getConfigurer(CsrfConfigurer.class);
        if (csrfConfigurer != null) {
            csrfConfigurer.ignoringRequestMatchers(new AntPathRequestMatcher("/jwt/tokens", "POST"));
        }
    }

    @Override
    public void configure(HttpSecurity builder) {
        AuthenticationManager authenticationManager =
                builder.getSharedObject(AuthenticationManager.class);

        var requestLoginPasswordFilter = new RequestLoginPasswordFilter();
        requestLoginPasswordFilter
                .authenticationManager(authenticationManager)
                .defaultUsernameJsonBodyParameter(defaultUsernameJsonBodyParameter)
                .defaultPasswordJsonBodyParameter(defaultPasswordJsonBodyParameter)
                .nativeAppHeader(nativeAppHeader)
                .objectMapper(objectMapper);

        var requestJwtTokensFilter = new RequestJwtTokensFilter();
        requestJwtTokensFilter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);
        requestJwtTokensFilter.setRefreshTokenStringSerializer(this.refreshTokenStringSerializer);

        var jwtAuthenticationFilter = new AuthenticationFilter(
                builder.getSharedObject(AuthenticationManager.class),
                new JwtAuthenticationConverter(
                        this.accessTokenStringDeserializer,
                        this.refreshTokenStringDeserializer
                )
        );

        jwtAuthenticationFilter.setSuccessHandler(
                (request, response, authentication) -> CsrfFilter.skipRequest(request)
        );

        jwtAuthenticationFilter.setFailureHandler(
                (request, response, exception) -> response.sendError(HttpServletResponse.SC_FORBIDDEN)
        );

        var preAuthenticatedAuthenticationProvider = new PreAuthenticatedAuthenticationProvider();
        var daoAuthenticationProvider = new DaoAuthenticationProvider();

        preAuthenticatedAuthenticationProvider.setPreAuthenticatedUserDetailsService(
                new TokenAuthenticationUserDetailsService(this.jdbcTemplate));
        daoAuthenticationProvider.setUserDetailsService(daoUserDetailsService);

        var refreshTokenFilter = new RefreshTokenFilter();
        refreshTokenFilter.setAccessTokenStringSerializer(this.accessTokenStringSerializer);

        var jwtLogoutFilter = new JwtLogoutFilter(this.jdbcTemplate);

        builder.addFilterAfter(requestJwtTokensFilter, ExceptionTranslationFilter.class)
                .addFilterBefore(jwtAuthenticationFilter, CsrfFilter.class)
                .addFilterBefore(requestLoginPasswordFilter, ExceptionTranslationFilter.class)
                .addFilterAfter(refreshTokenFilter, ExceptionTranslationFilter.class)
                .addFilterAfter(jwtLogoutFilter, ExceptionTranslationFilter.class)
                .authenticationProvider(preAuthenticatedAuthenticationProvider)
                .authenticationProvider(daoAuthenticationProvider);
    }

    public JwtAuthenticationConfigurer refreshTokenStringSerializer(
            Function<Token, String> refreshTokenStringSerializer) {
        this.refreshTokenStringSerializer = refreshTokenStringSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer accessTokenStringSerializer(
            Function<Token, String> accessTokenStringSerializer) {
        this.accessTokenStringSerializer = accessTokenStringSerializer;
        return this;
    }

    public JwtAuthenticationConfigurer accessTokenStringDeserializer(
            Function<String, Token> accessTokenStringDeserializer) {
        this.accessTokenStringDeserializer = accessTokenStringDeserializer;
        return this;
    }

    public JwtAuthenticationConfigurer refreshTokenStringDeserializer(
            Function<String, Token> refreshTokenStringDeserializer) {
        this.refreshTokenStringDeserializer = refreshTokenStringDeserializer;
        return this;
    }

    public JwtAuthenticationConfigurer jdbcTemplate(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
        return this;
    }

    public JwtAuthenticationConfigurer daoUserDetailsService(UserDetailsService daoUserDetailsService) {
        this.daoUserDetailsService = daoUserDetailsService;
        return this;
    }

    public JwtAuthenticationConfigurer objectMapper(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        return this;
    }

    public JwtAuthenticationConfigurer defaultUsernameJsonBodyParameter(String defaultUsernameJsonBodyParameter) {
        this.defaultUsernameJsonBodyParameter = defaultUsernameJsonBodyParameter;
        return this;
    }

    public JwtAuthenticationConfigurer defaultPasswordJsonBodyParameter(String defaultPasswordJsonBodyParameter) {
        this.defaultPasswordJsonBodyParameter = defaultPasswordJsonBodyParameter;
        return this;
    }

    public JwtAuthenticationConfigurer nativeAppHeader(String nativeAppHeader) {
        this.nativeAppHeader = nativeAppHeader;
        return this;
    }
}
