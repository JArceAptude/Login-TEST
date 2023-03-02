package com.auth.security.authentication;

import com.auth.security.config.JwtService;
import com.auth.security.model.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    private final LogRepository logRepository;

    private AdminLog  adminLog =  new AdminLog();

    /**
     * Used to register users passing the RegisterRequest and Role of the user.
     * @param request RegisterRequest object.
     * @param role Role of the new user.
     * @return
     */
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
            creageLog("INSERT","The user was created successfully.", user.getEmail());
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        } catch (DataIntegrityViolationException e){
            creageLog("INSERT","An error has occurred while trying to register the user, please try again.", request.getEmail());
            return AuthenticationResponse.builder()
                    .error("An error has occurred while trying to register the user, please try again.").build();

        }catch (NoSuchElementException e){
            creageLog("INSERT","An error has ocurred while trying to register a null user, please try again.", request.getEmail());
            return AuthenticationResponse.builder()
                    .error("An error has ocurred while trying to register a null value, please try again.").build();

        } catch (Exception e) {
            creageLog("INSERT","An unknown error has occurred while trying to register the user, please try again.",request.getEmail());
            return AuthenticationResponse.builder()
                    .error("An unknown error has occurred while trying to register the user, please try again.").build();
        }

    }

    /**
     * Validates if the user and password provider are of an user registered in the database. If so, it returns
     * a valid  JwtToken for the User.
     * @param request AuthenticationRequest object. Email and Password.
     * @return
     */
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        try {
            User latestLoginUser = new User();

            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword()));
            var user = userRepository.findByEmail(request.getEmail())
                    .orElseThrow();
            var jwtToken = jwtService.generateToken(user);


            latestLoginUser = updateLastLogin(user);
            userRepository.save(latestLoginUser);
            creageLog("LOGIN","The token was created successfully.", user.getEmail());
            return AuthenticationResponse.builder()
                    .token(jwtToken)
                    .build();
        } catch (BadCredentialsException e){
            creageLog("LOGIN","Bad credentials: password or email are invalid.", request.getEmail());
            return AuthenticationResponse.builder()
                    .error("Username or password are invalid, please try with a valid credentials.").build();
        }catch (Exception e){
            creageLog("LOGIN","An error occurred when trying to authenticate the user.", request.getEmail());

            return AuthenticationResponse.builder()
                    .error("An error occurred when trying to authenticate the user.").build();
        }

    }

    /**
     * Updates the data of a User.
     * @param request New data for the user.
     * @param id Id of the user.
     * @param role Role of the user that is updating the date of the modified user.
     * @return
     */
    public AuthenticationResponse update(RegisterRequest request, Integer id, Role role){
        try{
            User newUser = new User();
            User oldUser = userRepository.findById(id).get();
            User userID = userRepository.findByEmail(SecurityContextHolder.getContext().getAuthentication().getName()).orElseThrow();

            if(role == Role.USER && oldUser.getRole() == Role.USER && request.getRole() == Role.USER){
                if(userID.getId() == id){
                    oldUser.setFirstname(request.getFirstname());
                    oldUser.setLastname(request.getLastname());
                    oldUser.setEmail(request.getEmail());
                    oldUser.setPassword(passwordEncoder.encode(request.getPassword()));
                    oldUser.setIsActive(request.getIsActive());
                    oldUser.setRole(request.getRole());

                    newUser = updateLastLogin(oldUser);
                    var jwtToken = jwtService.generateToken(newUser);
                    userRepository.save(newUser);
                    creageLogId("UPDATE", "User updated successfully.",userID.getId());
                    return AuthenticationResponse.builder()
                            .token(jwtToken)
                            .build();
                }
                creageLogId("UPDATE", "User tried to update another account, please try with your account.",userID.getId());
                return AuthenticationResponse.builder()
                        .error("User tried to update another account, please try with your account.").build();
            }

            if(role == Role.MODERATOR && (oldUser.getRole() == Role.MODERATOR || oldUser.getRole() == Role.USER) && (request.getRole() != Role.ADMIN)){
                oldUser.setFirstname(request.getFirstname());
                oldUser.setLastname(request.getLastname());
                oldUser.setEmail(request.getEmail());
                oldUser.setPassword(passwordEncoder.encode(request.getPassword()));
                oldUser.setIsActive(request.getIsActive());
                oldUser.setRole(request.getRole());

                newUser = updateLastLogin(oldUser);
                var jwtToken = jwtService.generateToken(newUser);
                userRepository.save(newUser);
                creageLogId("UPDATE", "User updated successfully.",userID.getId());
                return AuthenticationResponse.builder()
                        .token(jwtToken)
                        .build();
            }

            if (role == Role.ADMIN &&(oldUser.getRole() == Role.ADMIN || oldUser.getRole() == Role.MODERATOR || oldUser.getRole() == Role.USER)){
                oldUser.setFirstname(request.getFirstname());
                oldUser.setLastname(request.getLastname());
                oldUser.setEmail(request.getEmail());
                oldUser.setPassword(passwordEncoder.encode(request.getPassword()));
                oldUser.setIsActive(request.getIsActive());
                oldUser.setRole(request.getRole());

                newUser = updateLastLogin(oldUser);
                var jwtToken = jwtService.generateToken(newUser);
                userRepository.save(newUser);
                creageLogId("UPDATE", "User updated successfully.",userID.getId());
                return AuthenticationResponse.builder()
                        .token(jwtToken)
                        .build();
            }
            creageLogId("UPDATE", "You don't have enough access to do this action",userID.getId());
            return AuthenticationResponse.builder()
                    .error("You don't have enough access to do this action.").build();
        }catch (Exception e){
            creageLog("UPDATE", "Something when wrong while updating",SecurityContextHolder.getContext().getAuthentication().getName());
            return AuthenticationResponse.builder()
                    .error("Something when wrong while updating").build();
        }
    }

    /**
     * Changes the isActive status from the user from True to False. Doesn't delete the user.
     * @param id Id of the user to Delete
     * @param role Role of the user that is Deleting the first user.
     * @return
     */
    public AuthenticationResponse delete(Integer id, Role role){
        try{
            User deletedUser = new User();

            User userQuery = userRepository.findById(id).get();
            if(role == Role.MODERATOR && (userQuery.getRole() == Role.MODERATOR
                    || userQuery.getRole() == Role.USER)) {

                userQuery.setIsActive(false);

                deletedUser = updateLastLogin(userQuery);

                userRepository.save(deletedUser);
                creageLog("DELETE", "Successfully deleted.",SecurityContextHolder.getContext().getAuthentication().getName());
                return AuthenticationResponse.builder().build();
            }else  if (role == Role.ADMIN &&(userQuery.getRole() == Role.ADMIN
                        || userQuery.getRole() == Role.MODERATOR
                        || userQuery.getRole() == Role.USER)) {
                userQuery.setIsActive(false);

                deletedUser = updateLastLogin(userQuery);

                userRepository.save(deletedUser);
                creageLog("DELETE", "Successfully deleted.",SecurityContextHolder.getContext().getAuthentication().getName());
                return AuthenticationResponse.builder().build();
            }
            creageLog("DELETE", "You don't have enough access to do this action.",SecurityContextHolder.getContext().getAuthentication().getName());
            return AuthenticationResponse.builder()
                    .error("You don't have enough access to do this action.").build();
        }catch (Exception e){
            creageLog("DELETE", "Something when wrong while deleting.",SecurityContextHolder.getContext().getAuthentication().getName());
            return AuthenticationResponse.builder()
                 .error("Something when wrong while deleting.").build();
        }
    }

    /**
     * Generates a new token with an extended expiration date for the current user.
     * @return
     */
    public AuthenticationResponse refreshToken(){
        try{
            User user = userRepository.findByEmail(SecurityContextHolder.getContext()
                    .getAuthentication()
                    .getName())
                    .orElseThrow();
            String jwtRefreshToken = jwtService.generateTokenRefreshToken(user);

            creageLog("LOGIN","The token was created successfully.", user.getEmail());
            return AuthenticationResponse.builder()
                    .refreshToken(jwtRefreshToken)
                    .build();
        }catch (Exception e){
            return AuthenticationResponse.builder()
                    .error("Something when wrong while generating the refresh token.").build();
        }
    }

    public List<User> getUsers(){
        try{
            return userRepository.findAll();
        }catch (Exception e){
            return Collections.emptyList();
        }
    }
    private User updateLastLogin(User user){
        Date date = new Date();

        user.setLastLogin(date);
        return  user;
    }

    private void creageLog(String action, String message, String username){
        try {
            User user = userRepository.findByEmail(username).orElseThrow();
            adminLog.setAction(action);
            adminLog.setDateAction(new Date());
            adminLog.setMessage(message);
            adminLog.setUser(user);
            logRepository.save(adminLog);
        }catch (NoSuchElementException e){
            System.out.println(e.getMessage());
        }
    }

    private void creageLogId(String action, String message, Integer id){
        User user = userRepository.findById(id).orElseThrow();
        adminLog.setAction(action);
        adminLog.setDateAction(new Date());
        adminLog.setMessage(message);
        adminLog.setUser(user);
        logRepository.save(adminLog);
    }
}
