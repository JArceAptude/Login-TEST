package com.auth.security.authentication;

import com.auth.security.model.Role;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private final AuthenticationService authService;
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request, Role.USER));
    }

    @PostMapping("/register/mod")
    @PreAuthorize("hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> modRegister(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request, Role.MODERATOR));
    }

    @PostMapping("/register/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<AuthenticationResponse> adminRegister(@RequestBody RegisterRequest request){
        return ResponseEntity.ok(authService.register(request, Role.ADMIN));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request){
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @PutMapping("/update/{id}")
    @PreAuthorize("hasAuthority('USER') or hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    public ResponseEntity<AuthenticationResponse> userUpdate(@RequestBody RegisterRequest request,@PathVariable("id") Integer id){
        return ResponseEntity.ok(authService.update(request, id, Role.USER));
    }

    @PutMapping("/update/mod/{id}")
    @PreAuthorize("hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    public ResponseEntity<AuthenticationResponse> modUpdate(@RequestBody RegisterRequest request,@PathVariable("id") Integer id){
        return ResponseEntity.ok(authService.update(request, id, Role.MODERATOR));
    }

    @PutMapping("/update/admin/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<AuthenticationResponse> adminUpdate(@RequestBody RegisterRequest request,@PathVariable("id") Integer id){
        return ResponseEntity.ok(authService.update(request, id, Role.ADMIN));
    }

    @DeleteMapping("/delete/mod/{id}")
    @PreAuthorize("hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    public ResponseEntity<AuthenticationResponse> deleteMod(@PathVariable("id") Integer id, Role role){
        return ResponseEntity.ok(authService.delete(id, Role.MODERATOR));
    }

    @DeleteMapping("/delete/admin/{id}")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<AuthenticationResponse> deleteAdmin(@PathVariable("id") Integer id, Role role){
        return ResponseEntity.ok(authService.delete(id, Role.ADMIN));
    }
}
