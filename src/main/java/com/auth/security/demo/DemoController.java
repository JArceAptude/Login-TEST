package com.auth.security.demo;

import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/hi")
    public ResponseEntity<String> sayHello(){
        return ResponseEntity.ok("Hello from secured endpoint");
    }
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/user")
    @PreAuthorize("hasAuthority('USER') or hasAuthority('MODERATOR') or hasAuthority('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/mod")
    @PreAuthorize("hasAuthority('MODERATOR') OR hasAuthority('ADMIN')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }
}
