package com.auth.security.model.service;

import com.auth.security.model.Permission;
import com.auth.security.model.PermissionRequest;
import com.auth.security.model.ResponseObject;
import com.auth.security.model.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class PermissionService {

    @Autowired
    private final PermissionRepository permissionRepository;

    public Permission save(PermissionRequest request){

        var permission = Permission.builder()
                .id(getTotalPermissions()+1)
                .name(request.getName())
                .description(request.getDescription())
                .roles(request.getRoles())
                .build();

        return permissionRepository.save(permission);
    }

    public List<Permission> getAll(){

        val a = SecurityContextHolder.getContext().getAuthentication().getName();

        return permissionRepository.findAll();
    }

    public ResponseObject getById(Integer id){
        try{
            return new ResponseObject(Optional.of(permissionRepository.findById(id).get()), "") ;
        } catch (NoSuchElementException nSEE){
            return new ResponseObject(null, nSEE.getMessage());
        }
    }

    public Permission update(Permission permission){
        return permissionRepository.save(permission);
    }

    public void delete(Integer id){
        permissionRepository.deleteById(id);
    }

    private int getTotalPermissions(){
        List<Permission> permissions = permissionRepository.findAll();
        if(permissions.isEmpty()){
            return 0;
        }
        return permissions.size();
    }
}