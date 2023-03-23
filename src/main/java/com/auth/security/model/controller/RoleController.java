package com.auth.security.model.controller;

import com.auth.security.model.ResponseObject;
import com.auth.security.model.Role;
import com.auth.security.model.RoleRequest;
import com.auth.security.model.service.RoleService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/role")
public class RoleController {

    @Autowired
    private RoleService roleService;

    @PostMapping("/new")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Role> saveRole(@RequestBody RoleRequest role){
        return ResponseEntity.ok(roleService.saveRole(role));
        //return ResponseEntity.ok(roleService.saveANewRole());
    }
    @GetMapping("/all")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<List<Role>> getAllRoles(){
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @GetMapping("/read/{id}")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ResponseObject> getRoleById(@RequestParam Integer id){
        return ResponseEntity.ok(roleService.getById(id));
    }

}
