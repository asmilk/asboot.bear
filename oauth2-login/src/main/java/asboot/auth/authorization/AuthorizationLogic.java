package asboot.auth.authorization;

import java.util.List;

import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Component("authz")
public class AuthorizationLogic {

	public boolean decide(OAuth2AuthenticationToken token, List<String> role,
			MethodSecurityExpressionOperations operations) {
		log.info("token:{}", token);
//		log.info("principal:{}", principal);
		log.info("operations:{}", operations);

//		List<String> role = principal.getClaimAsStringList("role");
		log.info("role:{}", role);
		boolean a = role.contains("");
		return true;
	}

}
