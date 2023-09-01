package asboot.auth.config;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import asboot.auth.federation.OktaOAuth2AuthorizationRowMapper;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

	private static final String LOGIN_FORM_URL = "/login";
	private static final String CONSENT_PAGE_URL = "/oauth2/consent";

	@Value("${jwk.public-key}")
	public RSAPublicKey publicKey;

	@Value("${jwk.private-key}")
	public RSAPrivateKey privateKey;

	@Bean
	// DefaultOidcUserInfoMapper
	Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper(UserDetailsService service) {
		return context -> {
			OAuth2AccessToken accessToken = context.getAccessToken();
			OAuth2Authorization authorization = context.getAuthorization();
			Set<String> scopes = accessToken.getScopes();
			String name = authorization.getPrincipalName();
			UserDetails user = service.loadUserByUsername(name);

			Map<String, Object> claims = new HashMap<>();
			claims.put(StandardClaimNames.SUB, name);

			if (scopes.contains(OidcScopes.PROFILE)) {
				claims.put(StandardClaimNames.NAME, user.getUsername());
			}
			return new OidcUserInfo(claims);
		};
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper) throws Exception {

		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

		// @formatter:off
		http
			.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.authorizationEndpoint(authorizationEndpoint -> authorizationEndpoint
				// DefaultConsentPage.displayConsent
				.consentPage(CONSENT_PAGE_URL))
//			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
			.oidc(oidc -> oidc
				.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint
					.userInfoMapper(userInfoMapper)));
		
		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling(exceptions -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint(LOGIN_FORM_URL),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer(resourceServer -> resourceServer
				.jwt(Customizer.withDefaults()));
		// @formatter:on
		return http.build();
	}

	/*
	@Bean
	RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		// @formatter:off
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("messaging-client")
				.clientSecret("{noop}secret")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				.redirectUri("http://127.0.0.1:8080/authorized")
				.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope(OidcScopes.EMAIL)
				.scope(OidcScopes.ADDRESS)
				.scope(OidcScopes.PHONE)
				.scope("message.read")
				.scope("message.write")
				.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).build())
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
				.build();
		// @formatter:on

		// Save registered client's in db as if in-memory
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		registeredClientRepository.save(registeredClient);

		return registeredClientRepository;
	}
	*/

	@Bean
	OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		JdbcOAuth2AuthorizationService service = new JdbcOAuth2AuthorizationService(jdbcTemplate,
				registeredClientRepository);
		service.setAuthorizationRowMapper(new OktaOAuth2AuthorizationRowMapper(registeredClientRepository));
		return service;
	}

	@Bean
	OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		// Will be used by the ConsentController
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
		return context -> {
			OAuth2TokenType tokenType = context.getTokenType();
			AuthorizationGrantType grantType = context.getAuthorizationGrantType();

			if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(grantType)
					|| AuthorizationGrantType.REFRESH_TOKEN.equals(grantType)) {
				if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)
						|| OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {

					Authentication principal = context.getPrincipal();
					List<String> authorities = principal.getAuthorities().stream().map(item -> item.getAuthority())
							.toList();
					log.info("authorities:{}", authorities);
					context.getClaims().claims(claims -> claims.put("role", new ArrayList<String>(authorities)));
				}
			}
		};
	}

	@Bean
	JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = new RSAKey.Builder(this.publicKey).privateKey(this.privateKey)
				.keyID(UUID.randomUUID().toString()).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}

	@Bean
	JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/*
	@Bean
	AuthorizationServerSettings authorizationServerSettings() {
		// @formatter:off
		return AuthorizationServerSettings.builder()
				.issuer("https://example.com")
				.authorizationEndpoint("/oauth2/authorize") //
				.deviceAuthorizationEndpoint("/oauth2/device_authorization")
				.deviceVerificationEndpoint("/oauth2/device_verification")
				.tokenEndpoint("/oauth2/token")
				.tokenIntrospectionEndpoint("/oauth2/introspect")
				.tokenRevocationEndpoint("/oauth2/revoke")
				.jwkSetEndpoint("/oauth2/jwks")
				.oidcLogoutEndpoint("/connect/logout")
				.oidcUserInfoEndpoint("/userinfo")
				.oidcClientRegistrationEndpoint("/connect/register")
				.build();
		// @formatter:on
	}
	*/

	@Bean
	EmbeddedDatabase embeddedDatabase() {
		// @formatter:off
		return new EmbeddedDatabaseBuilder()
				.generateUniqueName(true)
				.setType(EmbeddedDatabaseType.H2)
				.setScriptEncoding("UTF-8")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql")
				.addScript("org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql")
				.build();
		// @formatter:on
	}

}
