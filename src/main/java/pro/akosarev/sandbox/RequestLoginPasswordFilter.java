package pro.akosarev.sandbox;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class RequestLoginPasswordFilter extends OncePerRequestFilter {

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private ObjectMapper objectMapper;
    private String defaultUsernameJsonBodyParameter = "username";
    private String defaultPasswordJsonBodyParameter = "password";
    private String nativeAppHeader = "X-native";
    private RequestMatcher requestMatcher = new AntPathRequestMatcher("/jwt/tokens", HttpMethod.POST.name());
    private AuthenticationManager authenticationManager;
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        if (this.requestMatcher.matches(request)) {
            try {
                var isNative = checkNativeHeader(request);
                if (!isNative) {
                    response.sendError(HttpServletResponse.SC_BAD_REQUEST);
                    return;
                }
                UsernamePasswordAuthenticationToken authRequest = convert(request);
                if (authRequest == null) {
                    this.logger.trace("Did not process authentication request on transform to UsernamePasswordAuthenticationToken");
                    chain.doFilter(request, response);
                    return;
                }

                String username = authRequest.getName();
                this.logger.trace(LogMessage.format("Found username '%s'", username));

                Authentication authResult = this.authenticationManager.authenticate(authRequest);
                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authResult);
                this.securityContextHolderStrategy.setContext(context);
                if (this.logger.isDebugEnabled()) {
                    this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
                }
                this.securityContextRepository.saveContext(context, request, response);
            } catch (AuthenticationException var8) {
                this.securityContextHolderStrategy.clearContext();
                this.logger.debug("Failed to process authentication request", var8);
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
                return;
            }

            chain.doFilter(request, response);
        }
        chain.doFilter(request, response);
    }

    private boolean checkNativeHeader(HttpServletRequest request) {
        return request.getHeader(this.nativeAppHeader) != null;
    }

    private UsernamePasswordAuthenticationToken convert(HttpServletRequest request) throws IOException {
        try {
            var jsonRequest = this.objectMapper.readTree(request.getReader());
            var username = jsonRequest.get(defaultUsernameJsonBodyParameter).asText();
            var password= jsonRequest.get(defaultPasswordJsonBodyParameter).asText();
            if (username != null && password != null) {
                return new UsernamePasswordAuthenticationToken(username, password);
            }
        } catch (IOException e) {
            logger.error(e);
            return null;
        }
        return null;
    }

    public RequestLoginPasswordFilter objectMapper(ObjectMapper objectMapper) {
        Assert.notNull(objectMapper, "Should not be null");
        this.objectMapper = objectMapper;
        return this;
    }

    public RequestLoginPasswordFilter defaultUsernameJsonBodyParameter(String defaultUsernameJsonBodyParameter) {
        Assert.notNull(defaultUsernameJsonBodyParameter, "Should not be null");
        this.defaultUsernameJsonBodyParameter = defaultUsernameJsonBodyParameter;
        return this;
    }

    public RequestLoginPasswordFilter defaultPasswordJsonBodyParameter(String defaultPasswordJsonBodyParameter) {
        Assert.notNull(defaultPasswordJsonBodyParameter, "Should not be null");
        this.defaultPasswordJsonBodyParameter = defaultPasswordJsonBodyParameter;
        return this;
    }

    public RequestLoginPasswordFilter requestMatcher(RequestMatcher requestMatcher) {
        Assert.notNull(requestMatcher, "Should not be null");
        this.requestMatcher = requestMatcher;
        return this;
    }

    public RequestLoginPasswordFilter authenticationManager(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "Should not be null");
        this.authenticationManager = authenticationManager;
        return this;
    }

    public RequestLoginPasswordFilter nativeAppHeader(String nativeAppHeader) {
        Assert.notNull(nativeAppHeader, "Should not be null");
        this.nativeAppHeader = nativeAppHeader;
        return this;
    }
}
