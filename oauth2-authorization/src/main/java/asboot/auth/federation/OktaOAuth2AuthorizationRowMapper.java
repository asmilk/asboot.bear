package asboot.auth.federation;

import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import com.fasterxml.jackson.databind.ObjectMapper;

public class OktaOAuth2AuthorizationRowMapper extends OAuth2AuthorizationRowMapper {

	public OktaOAuth2AuthorizationRowMapper(RegisteredClientRepository registeredClientRepository) {
		super(registeredClientRepository);
		ObjectMapper objectMapper = this.getObjectMapper();
		objectMapper.addMixIn(Long.class, LongMixin.class);
		this.setObjectMapper(objectMapper);
	}

}
