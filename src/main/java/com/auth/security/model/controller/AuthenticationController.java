package com.auth.security.model.controller;

import com.auth.security.authentication.*;
import com.auth.security.model.service.AuthenticationService;
import com.auth.security.model.Role;
import com.auth.security.model.User;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * <h2>Controller for the authentication functionality.</h2>
 * This controller contains all the functionality for user management and authentication management.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authService;

     /**
     * Endpoint for the registration of users with the role USER.
     *
     * Invokes the register method of AuthenticationService
     *
     * @param request RegisterRequest object. User data.
     * @return ResponseEntity
     */
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * Endpoint for user Authentication.
     * @param request AuthenticationRequest object. Email and Password.
     * @return ResponseEntity
     */
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authService.authenticate(request));
    }

    /**
     * Endpoint for Users with Role USER, MODERATOR or ADMIN to update data of a USER.
     * @param request RegisterRequest object with the new user data.
     * @param id Id of the Updated User.
     * @return ResponseEntity
     */
    @PutMapping("/update/{id}")
    @PreAuthorize("hasAuthority('update_user') or hasAuthority('update_all_users')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> userUpdate(@RequestBody RegisterRequest request,@PathVariable("id") Integer id){
        return ResponseEntity.ok(authService.update(request, id));
    }

    /**
     * Endpoint for Users to delete another User
     * @param id Id of the User to Delete
     * @return ResponseEntity
     */
    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAuthority('delete_all_users') or hasAuthority('delete_users')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> delete(@PathVariable("id") Integer id){
        return ResponseEntity.ok(authService.delete(id));
    }

    /**
     * Endpoint to obtain a list of all the users in the database.
     * @return List User
     */
    @GetMapping("/getAll")
    @PreAuthorize("hasAuthority('read_all_users')")
    public List<User> getAll(){
        return authService.getUsers();
    }

    /**
     * Endpoint that updates the expiration date of the JwtToken of the User that calls this endpoint.
     * @return ResponseEntity
     */
    @GetMapping("/refreshToken")
    @PreAuthorize("hasAuthority('refresh_token')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> refreshToken(){
        return ResponseEntity.ok(authService.refreshToken());
    }

    @PostMapping("/recoverPassword")
    @SecurityRequirement(name = "Bearer Authentication")
    public String recoverPassword(PasswordRequest request){
        return authService.recoverPassword(request);
    }

    @PostMapping("/resetPassword")
    public String resetPassword(NewPasswordRequest request){
        return authService.resetPassword(request);
    };
}
