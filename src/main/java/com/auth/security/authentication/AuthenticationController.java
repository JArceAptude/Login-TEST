package com.auth.security.authentication;

import com.auth.security.model.Role;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import com.auth.security.model.User;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.responses.*;
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
        return ResponseEntity.ok(authService.register(request, Role.USER));
    }

    /**
     * Endpoint for the registration of users with the role MODERATOR.
     * @param request RegisterRequest object. User data.
     * @return ResponseEntity
     */
    @PostMapping("/register/mod")
    @PreAuthorize("hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> modRegister(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request, Role.MODERATOR));
    }

    /**
     * Endpoint for the registration of users with the role ADMIN.
     * @param request RegisterRequest object. User data.
     * @return ResponseEntity
     */
    @PostMapping("/register/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> adminRegister(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request, Role.ADMIN));
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
    @PreAuthorize("hasAuthority('USER') or hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> userUpdate(@RequestBody RegisterRequest request,@PathVariable("id") Integer id){
        return ResponseEntity.ok(authService.update(request, id, Role.USER));
    }

    /**
     * Endpoint for Users with Role MODERATOR or ADMIN to update data of a MODERATOR.
     * @param request RegisterRequest object with the new user data.
     * @param id Id of the Updated User.
     * @return ResponseEntity
     */
    @PutMapping("/update/mod/{id}")
    @PreAuthorize("hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> modUpdate(@RequestBody RegisterRequest request,@PathVariable("id") Integer id){
        return ResponseEntity.ok(authService.update(request, id, Role.MODERATOR));
    }

    /**
     * Endpoint for Users with Role ADMIN to update data of an ADMIN.
     * @param request RegisterRequest object with the new user data.
     * @param id Id of the Updated User.
     * @return ResponseEntity
     */
    @PutMapping("/update/admin/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> adminUpdate(@RequestBody RegisterRequest request,@PathVariable("id") Integer id){
        return ResponseEntity.ok(authService.update(request, id, Role.ADMIN));
    }

    /**
     * Endpoint for Users to delete another User
     * @param id Id of the User to Delete
     * @param role Role of the current User
     * @return ResponseEntity
     */
    @DeleteMapping("/delete/mod/{id}")
    @PreAuthorize("hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> deleteMod(@PathVariable("id") Integer id, Role role){
        return ResponseEntity.ok(authService.delete(id, Role.MODERATOR));
    }

    /**
     * Endpoint for Users to delete another User
     * @param id Id of the User to Delete
     * @param role Role of the current User
     * @return ResponseEntity
     */
    @DeleteMapping("/delete/admin/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> deleteAdmin(@PathVariable("id") Integer id, Role role){
        return ResponseEntity.ok(authService.delete(id, Role.ADMIN));
    }

    /**
     * Endpoint to obtain a list of all the users in the database.
     * @return List User
     */
    @GetMapping("/getAll")
    public List<User> getAll(){
        return authService.getUsers();
    }

    /**
     * Endpoint that updates the expiration date of the JwtToken of the User that calls this endpoint.
     * @return ResponseEntity
     */
    @GetMapping("/refreshToken")
    @PreAuthorize("hasAuthority('USER') or hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> refreshToken(){
        return ResponseEntity.ok(authService.refreshToken());
    }
}
