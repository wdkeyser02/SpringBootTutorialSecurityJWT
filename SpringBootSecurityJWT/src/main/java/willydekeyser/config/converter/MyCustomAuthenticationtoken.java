package willydekeyser.config.converter;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import willydekeyser.config.MyUser;

public class MyCustomAuthenticationtoken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;
	MyUser myUser;

	public MyCustomAuthenticationtoken(Collection<? extends GrantedAuthority> authorities, MyUser myUser) {
		super(authorities);
		this.myUser = myUser;
	}

	@Override
	public boolean isAuthenticated() {
		return true;
	}

	
	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public String getName() {
		return myUser.getUsername();
	}

	@Override
	public Object getPrincipal() {
		return myUser;
	}

}
