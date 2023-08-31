package asboot.auth.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/res")
public class ResourceController {

	@GetMapping("/check/{uid}")
	@PreAuthorize("@authz.check(#root, authentication, principal, #uid)")
	public String check(@PathVariable @P("uid") String uid) {
		return "check:" + uid;
	}

	@PreAuthorize("principal.claims['role'] != null and principal.claims['role'].contains('ROLE_ADMIN')")
	@GetMapping("/claim/admin")
	public String admin() {
		return "claim_admin";
	}

	@PreAuthorize("principal.claims['role'] != null and principal.claims['role'].contains('ROLE_STAFF')")
	@GetMapping("/claim/staff")
	public String staff() {
		return "claim_staff";
	}

	@PreAuthorize("principal.claims['role'] != null and principal.claims['role'].contains('ROLE_USER')")
	@GetMapping("/claim/user")
	public String user() {
		return "claim_user";
	}

	@PreAuthorize("hasRole('ADMIN')")
	@GetMapping("/role/admin")
	public String roleAdmin() {
		return "role_admin";
	}

	@PreAuthorize("hasRole('STAFF')")
	@GetMapping("/role/staff")
	public String roleStaff() {
		return "role_staff";
	}

	@PreAuthorize("hasRole('USER')")
	@GetMapping("/role/user")
	public String roleUser() {
		return "role_user";
	}

	@PreAuthorize("hasAuthority('SCOPE_email')")
	@GetMapping("/auth/scp/email")
	public String getEmail() {
		return "auth_scope_email";
	}

	@PreAuthorize("hasAuthority('SCOPE_message.read')")
	@GetMapping("/auth/scp/msg/read")
	public String readMessage() {
		return "auth_scope_msg_read";
	}

	@PreAuthorize("hasAuthority('SCOPE_message.write')")
	@GetMapping("/auth/scp/msg/write")
	public String writeMessage() {
		return "auth_scope_msg_write";
	}

}
