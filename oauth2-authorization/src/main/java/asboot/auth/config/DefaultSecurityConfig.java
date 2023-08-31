package asboot.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import asboot.auth.federation.FederatedIdentityAuthenticationSuccessHandler;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.authorizeHttpRequests(authorize -> authorize
				.requestMatchers("/assets/**", "/webjars/**", "/login").permitAll()
				.anyRequest().authenticated())
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.formLogin(formLogin -> formLogin
				.loginPage("/login"))
			.oauth2Login(oauth2Login -> oauth2Login
				.loginPage("/login")
				.successHandler(authenticationSuccessHandler()));
		// @formatter:on
		return http.build();
	}

	private AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new FederatedIdentityAuthenticationSuccessHandler();
	}

	@Bean
	UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withUsername("admin").password("{noop}123456").roles("ADMIN").build());
		manager.createUser(User.withUsername("staff").password("{noop}123456").roles("STAFF").build());
		manager.createUser(User.withUsername("user").password("{noop}123456").roles("USER").build());
		manager.createUser(User.withUsername("guest").password("{noop}123456").roles("GUEST").build());
		manager.createUser(User.withUsername("hacker").password("{noop}123456").roles("HACKER").disabled(true).build());
		manager.createUser(
				User.withUsername("graduate").password("{noop}123456").roles("GRADUATE").accountLocked(true).build());
		manager.createUser(
				User.withUsername("former").password("{noop}123456").roles("FORMER").accountExpired(true).build());
		manager.createUser(User.withUsername("repeater").password("{noop}123456").roles("REPEATER")
				.credentialsExpired(true).build());

		return manager;
	}

	@Bean
	SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

}
