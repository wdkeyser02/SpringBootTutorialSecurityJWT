package willydekeyser.service;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import willydekeyser.config.MyJwtUser;
import willydekeyser.config.MyUser;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class TokenService {

    private final JwtEncoder encoder;

    public TokenService(JwtEncoder encoder) {
        this.encoder = encoder;
    }

	public String generateToken(Authentication authentication) {
		Set<String> authorities = authentication.getAuthorities().stream()
				.map(GrantedAuthority::getAuthority)
				.collect(Collectors.toSet());
		MyUser myUser = (MyUser) authentication.getPrincipal();
		MyJwtUser myJwtUser = new MyJwtUser(authentication.getName(), myUser.getFirstName(), myUser.getLastName(),
				myUser.getFullname(), myUser.getEmailaddress(), myUser.getBirthdate().toString(), myUser.getPassword(),
				myUser.isEnabled(), myUser.isAccountNonExpired(), myUser.isCredentialsNonExpired(),
				myUser.isAccountNonLocked(), authorities);
		Instant now = Instant.now();
		JwtClaimsSet claims = JwtClaimsSet.builder()
				.issuer(authentication.getName())
				.issuedAt(now)
				.expiresAt(now.plus(1, ChronoUnit.HOURS))
				.subject(authentication.getName())
				.claim("authorities", authorities)
				.claim("myuser", myJwtUser)
				.build();
		return this.encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
	}

}