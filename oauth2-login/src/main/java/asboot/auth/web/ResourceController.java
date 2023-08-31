package asboot.auth.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/res")
public class ResourceController {

	@PreAuthorize("@authz.decide(authentication, principal.claims['role'], #root)")
	@GetMapping("/decide")
	public String decide() {
		return "decide";
	}

	@PreAuthorize("principal.claims['role'] != null and principal.claims['role'].contains('ROLE_ADMIN')")
	@GetMapping("/claim/admin")
	public String claimAdmin() {
		return "claim_admin";
	}

	@PreAuthorize("principal.claims['role'] != null and principal.claims['role'].contains('ROLE_STAFF')")
	@GetMapping("/claim/staff")
	public String claimStaff() {
		return "claim_staff";
	}

	@PreAuthorize("principal.claims['role'] != null and principal.claims['role'].contains('ROLE_USER')")
	@GetMapping("/claim/user")
	public String claimUser() {
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

	@PreAuthorize("hasAuthority('ROLE_ADMIN')")
	@GetMapping("/auth/admin")
	public String auth_Admin() {
		return "auth_admin";
	}

	@PreAuthorize("hasAuthority('ROLE_STAFF')")
	@GetMapping("/auth/staff")
	public String authStaff() {
		return "auth_staff";
	}

	@PreAuthorize("hasAuthority('ROLE_USER')")
	@GetMapping("/auth/user")
	public String authUser() {
		return "auth_user";
	}

}
