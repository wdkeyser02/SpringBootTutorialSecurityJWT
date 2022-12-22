package willydekeyser.config.converter;

import java.time.LocalDate;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import willydekeyser.config.MyUser;

public class MyCustomAuthenticationConverter implements Converter<Jwt, MyCustomAuthenticationtoken> {

	@SuppressWarnings("unchecked")
	@Override
	public MyCustomAuthenticationtoken convert(Jwt source) {
		Map<String, String> user = (Map<String, String>) source.getClaims().get("myuser");
		Object authoritiesClaim = user.get("authorities");
		Set<GrantedAuthority> authorities = ((Collection<String>) authoritiesClaim).stream()
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
		MyUser myUser = new MyUser(user.get("username"), "", true, true, true, true, 
				authorities, user.get("firstName"), user.get("lastName"), user.get("emailaddress"), 
				LocalDate.parse(user.get("birthdate")));	
		return new MyCustomAuthenticationtoken(authorities, myUser);
	}

}
