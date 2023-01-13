package com.auth.security.authentication;

import com.auth.security.config.JwtService;
import com.auth.security.model.Role;
import com.auth.security.model.User;
import com.auth.security.model.UserRepository;
import com.sun.jdi.event.ExceptionEvent;
import lombok.RequiredArgsConstructor;
import org.hibernate.engine.jdbc.spi.SqlExceptionHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.w3c.dom.events.EventException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request, Role role) {
        try{
            var user = User.builder()
                    .firstname(request.getFirstname())
                    .lastname(request.getLastname())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .role(role)
                    .build();
            userRepository.save(user);
            var jwtToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        } catch (Exception e){
            return AuthenticationResponse.builder()
                    .error("The email: '" + request.getEmail() + "' has been taken.").build();
        }


    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
            var user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow();
            var jwtToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        } catch (Exception e){
            return AuthenticationResponse.builder()
                    .error("An error occurred when trying to authenticate the user.").build();
        }

    }
}
