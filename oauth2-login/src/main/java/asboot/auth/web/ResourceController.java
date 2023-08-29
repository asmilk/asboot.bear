package asboot.auth.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
	
	@PreAuthorize("principal.claims['role'].contains('ROLE_ADMIN')")
	@GetMapping("/res/admin")
	public String admin() {
		return "admin";
	}
	
//	@PreAuthorize("principal.claims['role'].length>0")
	@PreAuthorize("@authz.decide(authentication, principal.claims['role'], #root)")
	@GetMapping("/res/staff")
	public String staff() {
		return "staff";
	}
	
	@PreAuthorize("principal.claims['role'][0] == 'ROLE_ADMIN'")
	@GetMapping("/res/user")
	public String user() {
		return "user";
	}
	
	@PreAuthorize("principal.claims['role'] == 'ROLE_GUEST'")
	@GetMapping("/res/guest")
	public String guest() {
		return "guest";
	}

}
