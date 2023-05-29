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

    /***
     * Endpoint for the creation of new permissions in which you can create a permission and assign
     * to a role.
     * @param request
     * @return
     */

    @PostMapping("/new")
    @PreAuthorize("hasAuthority('create_permissions')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Permission> newPermission(@RequestBody PermissionRequest request){
        return ResponseEntity.ok(permissionService.save(request));
    }

    /***
     * Endpoint to read a specific permission by its id.
     * @param id
     * @return
     */
    @GetMapping("/read/{id}")
    @PreAuthorize("hasAuthority('read_permissions')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<ResponseObject> getPermissionById(@RequestParam Integer id){
        return ResponseEntity.ok((permissionService.getById(id)));
    }

    /***
     * Endpoint for reading all permissions.
     * @return
     */

    @GetMapping("/read/all")
    @PreAuthorize("hasAuthority('read_permissions')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<List<Permission>> getAllPermissions(){
        return ResponseEntity.ok(permissionService.getAll());
    }

    /***
     * Endpoint for updating a permission by id.
     * @param id
     * @param permission
     * @return
     */

    @PutMapping("/update/{id}")
    @PreAuthorize("hasAuthority('update_permissions')")
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Permission> updatePermissionById(@RequestParam Integer id, @RequestBody PermissionRequest permission){
        return ResponseEntity.ok(permissionService.updateById(id, permission));
    }
}
