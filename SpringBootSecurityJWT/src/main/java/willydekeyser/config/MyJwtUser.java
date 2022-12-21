package willydekeyser.config;

import java.util.Set;

public record MyJwtUser(String username, 
		String firstName, 
		String lastName, 
		String fullname, 
		String emailaddress, 
		String birthdate, 
		String password, 
		boolean enabled, 
		boolean accountNonExpired,
		boolean credentialsNonExpired, 
		boolean accountNonLocked,
		Set<String> authorities) {

}
