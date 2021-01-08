package dev.gg.springsecurityjwt;

import dev.gg.springsecurityjwt.service.AuthenticationResponse;
import dev.gg.springsecurityjwt.service.MyUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

import static org.springframework.http.ResponseEntity.ok;

@Controller
public class HelloResource {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private MyUserDetailsService myUserDetailsService;


    @RequestMapping({"/hello"})
    public ResponseEntity<String> hello() {
        return ok("Hello World");
    }


    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> auth(@RequestBody UserRequest userRequest) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userRequest.getUserName(), userRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException("pone las weas bien", e);
        }
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(userRequest.getUserName());
        String token = JwtUtil.generateToken(userDetails);
        return ok(new AuthenticationResponse(token));
    }

}
