package com.auth.security.authentication;

import com.auth.security.config.JwtService;
import com.auth.security.model.Role;
import com.auth.security.model.User;
import com.auth.security.model.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request, Role role) {
        try{
            Date date = new Date();

            var user = User.builder()
                    .firstname(request.getFirstname())
                    .lastname(request.getLastname())
                    .email(request.getEmail())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .dateJoined(date)
                    .lastLogin(date)
                    .isActive(true)
                    .role(role)
                    .build();
            userRepository.save(user);
            var jwtToken = jwtService.generateToken(user);
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        } catch (DataIntegrityViolationException e){

            return AuthenticationResponse.builder()
                    .error("An error has occurred while trying to register the user, please try again.").build();

        } catch (Exception e) {
            return AuthenticationResponse.builder()
                    .error("An unknown error has occurred while trying to register the user, please try again.").build();
        }

    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            User latestLoginUser = new User();

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
            var user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow();
            var jwtToken = jwtService.generateToken(user);


            latestLoginUser = updateLastLogin(user);
            userRepository.save(latestLoginUser);

            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        } catch (Exception e){
            return AuthenticationResponse.builder()
                    .error("An error occurred when trying to authenticate the user.").build();
        }

    }

    private User updateLastLogin(User user){
        Date date = new Date();

        user.setLastLogin(date);
        return  user;
    }
}
