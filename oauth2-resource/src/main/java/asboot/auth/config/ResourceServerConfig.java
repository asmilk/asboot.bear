/*
 * Copyright 2020-2022 the original author or authors.
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

import java.util.Collection;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;

/**
 * @author Joe Grandja
 * @since 0.0.1
 */
@EnableWebSecurity
@EnableMethodSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
//		http
//			.securityMatcher("/messages/**")
//				.authorizeHttpRequests()
//					.requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
//					.and()
//			.oauth2ResourceServer()
//				.jwt();
		// @formatter:off
		http
			.authorizeHttpRequests(authorize -> 
				authorize
					.requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
					.anyRequest().authenticated())
			.oauth2ResourceServer(oauth2ResourceServer ->
//				oauth2ResourceServer.jwt(Customizer.withDefaults())
				oauth2ResourceServer.jwt(jwt -> jwt.jwtAuthenticationConverter(new Converter<Jwt, AbstractAuthenticationToken>(){

					@Override
					public AbstractAuthenticationToken convert(Jwt source) {
						JwtAuthenticationConverter conver = new JwtAuthenticationConverter();
						conver.setJwtGrantedAuthoritiesConverter(new Converter<Jwt, Collection<GrantedAuthority>>(){

							@Override
							public Collection<GrantedAuthority> convert(Jwt source) {
								Collection<GrantedAuthority> scope = new JwtGrantedAuthoritiesConverter().convert(source);
								JwtGrantedAuthoritiesConverter roleConverter = new JwtGrantedAuthoritiesConverter();
								roleConverter.setAuthorityPrefix("");
								roleConverter.setAuthoritiesClaimName("role");
								Collection<GrantedAuthority> role = roleConverter.convert(source);
								scope.addAll(role);
								return scope;
							}
							
						});
						return conver.convert(source);
					}
					
				}))
			);
		// @formatter:on
		return http.build();
	}

	@Bean
	RoleHierarchy roleHierarchy() {
		RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
		roleHierarchy.setHierarchy("ROLE_ADMIN > ROLE_STAFF > ROLE_USER" + System.getProperty("line.separator")
				+ "ROLE_A > ROLE_B > ROLE_C");
		return roleHierarchy;

	}

	@Bean
	MethodSecurityExpressionHandler methodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
		DefaultMethodSecurityExpressionHandler expressionHandler = new DefaultMethodSecurityExpressionHandler();
		expressionHandler.setRoleHierarchy(roleHierarchy);
		return expressionHandler;
	}

	@Bean
	HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

}
