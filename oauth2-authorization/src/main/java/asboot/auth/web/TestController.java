package asboot.auth.web;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class TestController {

	@Autowired
	private JWKSource<SecurityContext> jwkSource;

	@GetMapping("/test")
	public String test() {
		NimbusJwtEncoder jwtEncoder = new NimbusJwtEncoder(this.jwkSource);
		log.info("jwtEncoder:{}", jwtEncoder);
		return "test";
	}

}
