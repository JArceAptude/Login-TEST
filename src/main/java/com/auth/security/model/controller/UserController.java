package com.auth.security.model.controller;

import com.auth.security.authentication.RegisterRequest;
import com.auth.security.model.ResponseObject;
import com.auth.security.model.User;
import com.auth.security.model.service.UserService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/user")
public class UserController {

    @Autowired
    private UserService userService;

    /***
     * Endpoint to read all Active users.
     * Active users are the ones that have its attribute isActive.
     * @return
     */
    @GetMapping("/all")
    @PreAuthorize("hasAuthority('edit_all_users')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<List<Optional>> getAllActiveUsers(){
        return ResponseEntity.ok(userService.getAllActiveUsers());
    }

    /***
     * Endpoint to read a specific user by its id.
     * @param id
     * @return
     */
    @GetMapping("/id/{id}")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ResponseObject> getById(@RequestParam Integer id){
        return ResponseEntity.ok(userService.getById(id));
    }

    /***
     * Endpoint to read a specific user by its username.
     * @param username
     * @return
     */
    @GetMapping("/username/{username}")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ResponseObject> getByUsername(@RequestParam String username){
        return ResponseEntity.ok(userService.getByUsername(username));
    }

    /***
     * Endpoint to update a user by its id.
     * @param id
     * @param request
     * @return
     */
    @PutMapping("/update/{id}")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<User> updateUser(@RequestParam Integer id, @RequestBody RegisterRequest request){
        return ResponseEntity.ok(userService.updateUserById(id, request));
    }

}
