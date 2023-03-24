package com.auth.security.model.controller;

import com.auth.security.model.Permission;
import com.auth.security.model.PermissionRequest;
import com.auth.security.model.ResponseObject;
import com.auth.security.model.service.PermissionService;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/permission")
@RequiredArgsConstructor
public class PermissionController {

    @Autowired
    private final PermissionService permissionService;

    @PostMapping("/new")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Permission> newPermission(@RequestBody PermissionRequest request){
        return ResponseEntity.ok(permissionService.save(request));
    }

    @GetMapping("/read/{id}")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ResponseObject> getPermissionById(@RequestParam Integer id){
        return ResponseEntity.ok((permissionService.getById(id)));
    }

    @GetMapping("/read/all")
    @PreAuthorize("hasAuthority('edit_all_users')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<List<Permission>> getAllPermissions(){
        return ResponseEntity.ok(permissionService.getAll());
    }
}
