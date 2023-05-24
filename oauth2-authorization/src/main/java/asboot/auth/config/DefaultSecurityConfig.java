/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package asboot.auth.config;

import asboot.auth.federation.FederatedIdentityAuthenticationSuccessHandler;

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

/**
 * @author Joe Grandja
 * @author Steve Riesenberg
 * @since 1.1
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    // @formatter:off
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize ->
				authorize
					.requestMatchers("/assets/**", "/webjars/**", "/login").permitAll()
					.anyRequest().authenticated()
			)
			.formLogin(formLogin ->
				formLogin
					.loginPage("/login")
			)
			.oauth2Login(oauth2Login ->
				oauth2Login
					.loginPage("/login")
					.successHandler(authenticationSuccessHandler())
			);

		return http.build();
	}
	// @formatter:on

	private AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new FederatedIdentityAuthenticationSuccessHandler();
	}

    // @formatter:off
    @Bean
    UserDetailsService users() {
//		UserDetails user = User.withDefaultPasswordEncoder()
//				.username("user1")
//				.password("password")
//				.roles("USER")
//				.build();
//		return new InMemoryUserDetailsManager(user);
		
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

    // @formatter:on

    @Bean
    SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

    @Bean
    HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

}
