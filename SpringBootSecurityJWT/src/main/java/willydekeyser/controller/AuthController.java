package willydekeyser.controller;

import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import ch.qos.logback.classic.Logger;
import willydekeyser.service.TokenService;

@RestController
public class AuthController {

	private static final Logger LOG = (Logger) LoggerFactory.getLogger(AuthController.class);
	private final TokenService tokenService;
	
    public AuthController(TokenService tokenService) {
		this.tokenService = tokenService;
	}

	@PostMapping("/token")
    public String token(Authentication authentication) {
		LOG.debug("Token request for user: '{}'", authentication.getName());
		String token = tokenService.generateToken(authentication);
		LOG.debug("Token: {}", token);
		return token;
	}

}