package willydekeyser.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import willydekeyser.model.LoginRequest;
import willydekeyser.service.TokenService;

@RestController
public class AuthController {

	private static final Logger LOG = (Logger) LoggerFactory.getLogger(AuthController.class);
	private final TokenService tokenService;
	private final AuthenticationManager authenticationManager;
	
    public AuthController(TokenService tokenService, AuthenticationManager authenticationManager) {
		this.tokenService = tokenService;
		this.authenticationManager = authenticationManager;
	}

	@PostMapping("/token")
    public String tokenbybody(Authentication authentication) {
		LOG.debug("Token request for user: '{}'", authentication);
		String token = tokenService.generateToken(authentication);
		LOG.debug("Token: {}", token);
		return token;
	}
	
	@PostMapping("/tokenbybody")
    public String tokenByBody(@RequestBody LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));
		LOG.debug("Token request for user: '{}'", authentication);
		String token = tokenService.generateToken(authentication);
		LOG.debug("Token: {}", token);
		return token;
	}

}