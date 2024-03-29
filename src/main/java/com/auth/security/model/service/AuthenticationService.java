package com.auth.security.model.service;

import com.auth.security.authentication.*;
import com.auth.security.config.JwtService;
import com.auth.security.model.*;
import com.auth.security.model.repository.LogRepository;
import com.auth.security.model.repository.RoleRepository;
import com.auth.security.model.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.mail.MailException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
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
    private final RoleRepository roleRepository;
    private final RoleService roleService;

    private final MailService mailService;
    private AdminLog  adminLog =  new AdminLog();
    private int codeGenerated = 0;

    /**
     * Used to register users passing the RegisterRequest and Role of the user.
     * @param request RegisterRequest object.
     * @return AuthenticationResponse
     */
    public AuthenticationResponse register(RegisterRequest request) {
        try{
            String email = SecurityContextHolder.getContext().getAuthentication().getName();
            Role role = roleRepository.findById(request.getRoleId()).get();
            User registerUser;
            Date date = new Date();

            if(email.equals("anonymousUser")){
                var user = User.builder()
                        .id(findTotalUser()+1)
                        .firstname(request.getFirstname())
                        .lastname(request.getLastname())
                        .email(request.getEmail())
                        .password(passwordEncoder.encode(request.getPassword()))
                        .dateJoined(date)
                        .lastLogin(date)
                        .isActive(true)
                        .role(findLowestPriority())
                        .build();
                userRepository.save(user);
                var jwtToken = jwtService.generateToken(user);
                creageLog("INSERT","The user was created successfully.", user.getEmail());
                return AuthenticationResponse.builder()
                        .token(jwtToken)
                        .build();
            }else {
                registerUser = userRepository.findByEmail(SecurityContextHolder.getContext().getAuthentication().getName()).orElseThrow();
                if(registerUser.getRole().getPriority() > role.getPriority()){
                    var user = User.builder()
                            .id(findTotalUser()+1)
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
                }else if(registerUser.getRole().getPriority() < role.getPriority()){
                    var user = User.builder()
                            .id(findTotalUser()+1)
                            .firstname(request.getFirstname())
                            .lastname(request.getLastname())
                            .email(request.getEmail())
                            .password(passwordEncoder.encode(request.getPassword()))
                            .dateJoined(date)
                            .lastLogin(date)
                            .isActive(true)
                            .role(registerUser.getRole())
                            .build();
                    userRepository.save(user);
                    var jwtToken = jwtService.generateToken(user);
                    creageLog("INSERT","The user was created successfully.", user.getEmail());
                    return AuthenticationResponse.builder()
                            .token(jwtToken)
                            .build();
                }else if(registerUser.getRole().getPriority() == role.getPriority()){
                    var user = User.builder()
                            .id(findTotalUser()+1)
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
                }
                creageLog("INSERT","You don't have enough access.", request.getEmail());
                return AuthenticationResponse.builder()
                        .error("You don't have enough acess.")
                        .build();
            }
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
     * @return AuthenticationResponse
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
     * @return AuthenticationResponse
     */
    public AuthenticationResponse update(RegisterRequest request, Integer id){
        try{
            User newUser = new User();
            User oldUser = userRepository.findById(id).get();
            User requestedUser = userRepository.findByEmail(SecurityContextHolder.getContext().getAuthentication().getName()).orElseThrow();
            Role role = roleRepository.findById(request.getRoleId()).get();

            if(requestedUser.getRole().getPriority() > oldUser.getRole().getPriority()){
                oldUser.setFirstname(request.getFirstname());
                oldUser.setLastname(request.getLastname());
                oldUser.setEmail(request.getEmail());
                oldUser.setPassword(passwordEncoder.encode(request.getPassword()));
                oldUser.setIsActive(request.getIsActive());
                if((role.getPriority() >= oldUser.getRole().getPriority()) || (requestedUser.getRole().getPriority() >= role.getPriority())){
                    oldUser.setRole(role);
                }else{
                    oldUser.setRole(requestedUser.getRole());
                }
                newUser = updateLastLogin(oldUser);
                var jwtToken = jwtService.generateToken(newUser);
                userRepository.save(newUser);
                creageLogId("UPDATE", "User updated successfully.",requestedUser.getId());
                return AuthenticationResponse.builder()
                        .token(jwtToken)
                        .build();
            }else if(requestedUser.getRole().getPriority() == oldUser.getRole().getPriority()){
                if((requestedUser.getId() == oldUser.getId()) && (findLowestPriority(role.getPriority())) ){
                    oldUser.setFirstname(request.getFirstname());
                    oldUser.setLastname(request.getLastname());
                    oldUser.setEmail(request.getEmail());
                    oldUser.setPassword(passwordEncoder.encode(request.getPassword()));
                    oldUser.setIsActive(request.getIsActive());
                    if((role.getPriority() <= oldUser.getRole().getPriority()) && (requestedUser.getRole().getPriority() >= role.getPriority())){
                        oldUser.setRole(role);
                    }else{
                        oldUser.setRole(requestedUser.getRole());
                    }
                    newUser = updateLastLogin(oldUser);
                    var jwtToken = jwtService.generateToken(newUser);
                    userRepository.save(newUser);
                    creageLogId("UPDATE", "User updated successfully.",requestedUser.getId());
                    return AuthenticationResponse.builder()
                            .token(jwtToken)
                            .build();
                }else if((requestedUser.getId() == oldUser.getId()) && !(findLowestPriority(role.getPriority()))){
                    oldUser.setFirstname(request.getFirstname());
                    oldUser.setLastname(request.getLastname());
                    oldUser.setEmail(request.getEmail());
                    oldUser.setPassword(passwordEncoder.encode(request.getPassword()));
                    oldUser.setIsActive(request.getIsActive());
                    if((role.getPriority() <= oldUser.getRole().getPriority()) && (requestedUser.getRole().getPriority() >= role.getPriority())){
                        oldUser.setRole(role);
                    }else{
                        oldUser.setRole(requestedUser.getRole());
                    }
                    newUser = updateLastLogin(oldUser);
                    var jwtToken = jwtService.generateToken(newUser);
                    userRepository.save(newUser);
                    creageLogId("UPDATE", "User updated successfully.",requestedUser.getId());
                    return AuthenticationResponse.builder()
                            .token(jwtToken)
                            .build();
                }else if(!(findLowestPriority(role.getPriority()))){
                    oldUser.setFirstname(request.getFirstname());
                    oldUser.setLastname(request.getLastname());
                    oldUser.setEmail(request.getEmail());
                    oldUser.setPassword(passwordEncoder.encode(request.getPassword()));
                    oldUser.setIsActive(request.getIsActive());
                    if((role.getPriority() <= oldUser.getRole().getPriority()) && (requestedUser.getRole().getPriority() >= role.getPriority())){
                        oldUser.setRole(role);
                    }else{
                        oldUser.setRole(requestedUser.getRole());
                    }
                    newUser = updateLastLogin(oldUser);
                    var jwtToken = jwtService.generateToken(newUser);
                    userRepository.save(newUser);
                    creageLogId("UPDATE", "User updated successfully.",requestedUser.getId());
                    return AuthenticationResponse.builder()
                            .token(jwtToken)
                            .build();
                }else if((requestedUser.getId() != oldUser.getId())&&!(findLowestPriority(role.getPriority()))){
                    oldUser.setFirstname(request.getFirstname());
                    oldUser.setLastname(request.getLastname());
                    oldUser.setEmail(request.getEmail());
                    oldUser.setPassword(passwordEncoder.encode(request.getPassword()));
                    oldUser.setIsActive(request.getIsActive());
                    if((role.getPriority() >= oldUser.getRole().getPriority()) || (requestedUser.getRole().getPriority() >= role.getPriority())){
                        oldUser.setRole(role);
                    }else{
                        oldUser.setRole(requestedUser.getRole());
                    }
                    newUser = updateLastLogin(oldUser);
                    var jwtToken = jwtService.generateToken(newUser);
                    userRepository.save(newUser);
                    creageLogId("UPDATE", "User updated successfully.",requestedUser.getId());
                    return AuthenticationResponse.builder()
                            .token(jwtToken)
                            .build();
                }
                creageLogId("UPDATE", "User tried to update another account, please try with your account.",requestedUser.getId());
                return AuthenticationResponse.builder()
                        .error("User tried to update another account, please try with your account.").build();
            }
            creageLogId("UPDATE", "You don't have enough access to do this action",requestedUser.getId());
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
     * @return AuthenticationResponse
     */
    public AuthenticationResponse delete(Integer id){
        try{
            User deletedUser = userRepository.findById(id).get();
            User tokenUser = userRepository.findByEmail(SecurityContextHolder.getContext().getAuthentication().getName()).get();

            if(tokenUser.getRole().getPriority() > deletedUser.getRole().getPriority()){
                deletedUser.setIsActive(false);
                userRepository.save(deletedUser);
                creageLog("DELETE", "Successfully deleted.",tokenUser.getUsername());
                return AuthenticationResponse.builder().build();
            }else if(tokenUser.getRole().getPriority() == deletedUser.getRole().getPriority()){
                    deletedUser.setIsActive(false);
                    userRepository.save(deletedUser);
                    creageLog("DELETE", "Successfully deleted.",tokenUser.getUsername());
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
     * @return AuthenticationResponse
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

    /**
     * Executes the method findAll() from UserRepository to obtain all the users in the database.
     * If it fails, returns an empty list.
     * @return List
     */
    public List<User> getUsers(){
        try{
            return userRepository.findAll();
        }catch (Exception e){
            return Collections.emptyList();
        }
    }

    public String recoverPassword(PasswordRequest request){
        try {
            User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
            int code = (int) (100000 + Math.random() * 900000);
            codeGenerated = code;
            mailService.sendEmail(user.getEmail(),code, "Password Recovery Code","Your code is:");
            return "Your code has been sent.";
        }catch (NoSuchElementException e){
            creageLog("PASSWORDRECOVERY","An error has ocurred while trying to recover a password from an non existing email, please try again.", request.getEmail());
            AuthenticationResponse.builder()
                    .error("An error has ocurred while trying to recover a password from an non existing email, please try again.").build();
            return "";
        } catch (MailException mailException) {
            creageLog("PASSWORDRECOVERY","An error has ocurred while trying to send the mail, please try again.", request.getEmail());
            AuthenticationResponse.builder()
                    .error("An error has ocurred while trying to send the mail, please try again.").build();
            return "";
        }
    }

    public String resetPassword(NewPasswordRequest request){

        try{
            if (codeGenerated == request.getCode()){
                User user = userRepository.findByEmail(request.getEmail()).orElseThrow();
                user.setPassword(passwordEncoder.encode(request.getPassword()));
                userRepository.save(user);
                codeGenerated = 0;
                return "password successfully reset.";
            }
            return "Incorrect code, please try again.";
        }catch (NoSuchElementException e){
            creageLog("RESETPASSWORD","An error has ocurred while trying to reset the password, please try again.", request.getEmail());
            AuthenticationResponse.builder()
                    .error("An error has ocurred while trying to recover a password from an non existing email, please try again.").build();
            return "";
        }
    }

    /**
     * Updates the User's lastLogin attribute to match the current date.
     * @param user User
     * @return User
     */
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

    private boolean findLowestPriority(Integer priority){
        List<Role> roles = roleRepository.findAll();
        int max = 0;
        for (int i = 0; i < roles.size(); i++){
            if(roles.get(i).getPriority() > max){
                max = roles.get(i).getPriority();
            }
        }
        int min = max;
        for (int i = 0; i < roles.size(); i++){
            if(roles.get(i).getPriority() < min){
                min = roles.get(i).getPriority();
            }
        }

        if(min == priority){
            return true;
        }else {
            return false;
        }
    }

    private Role findLowestPriority(){
        List<Role> roles = roleRepository.findAll();
        int max = 0;
        for (int i = 0; i < roles.size(); i++){
            if(roles.get(i).getPriority() > max){
                max = roles.get(i).getPriority();
            }
        }
        int min = max;
        for (int i = 0; i < roles.size(); i++){
            if(roles.get(i).getPriority() < min){
                min = roles.get(i).getPriority();
            }
        }

        return roleService.getByPriority(min);
    }

    private int findTotalUser(){
        List<User> users = userRepository.findAll();
        if(users.isEmpty()){
            return 0;
        }
        return users.size();
    }
}
