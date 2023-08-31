package asboot.auth.authorization;

import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component("authz")
public class AuthorizationLogic {

	public boolean check(MethodSecurityExpressionOperations root, JwtAuthenticationToken token, Jwt jwt, String uid) {
		log.info("root:{}", root);
		log.info("token:{}", token);
		log.info("jwt:{}", jwt);
		log.info("uid:{}", uid);
		return true;
	}

}
