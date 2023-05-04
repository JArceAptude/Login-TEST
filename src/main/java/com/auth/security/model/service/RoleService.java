package com.auth.security.model.service;

import com.auth.security.model.ResponseObject;
import com.auth.security.model.Role;
import com.auth.security.model.RoleRequest;
import com.auth.security.model.repository.PermissionRepository;
import com.auth.security.model.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class RoleService {

    @Autowired
    private final RoleRepository roleRepository;

    @Autowired
    private final PermissionRepository permissionRepository;

    public List<Role> getAllRoles(){
        return roleRepository.findAll();
    }

    public Role saveRole(RoleRequest request){

        var role = Role.builder()
                .id(getTotalRoles()+1)
                .name(request.getName())
                .description(request.getDescription())
                .rolePermissions(permissionRepository.findAllById(request.getPermissionIds()))
                .build();

        return roleRepository.save(role);
    }

    public List<Role> getAll(){
        return roleRepository.findAll();
    }

    public ResponseObject getById(Integer id){
        try{
            return new ResponseObject(Optional.of(roleRepository.findById(id).get()), "");
        } catch (NoSuchElementException nSEE) {
            return new ResponseObject(null, nSEE.getMessage());
        }

    }

    public Role getByPriority(Integer priority){
        try{
            List<Role> roles = roleRepository.findAll();
            for(int i = 0; i < roles.size(); i++){
                if(roles.get(i).getPriority() == priority){
                    return roles.get(i);
                }
            }
            return null;
        }catch(Exception e){
            return null;
        }
    }

    public Role update(Role permission){
        return roleRepository.save(permission);
    }

    public void delete(Integer id){
        roleRepository.deleteById(id);
    }

    private int getTotalRoles(){
        List<Role> roles = roleRepository.findAll();
        if(roles.isEmpty()){
            return 0;
        }
        return roles.size();
    }
}
