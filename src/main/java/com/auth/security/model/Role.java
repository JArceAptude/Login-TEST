package com.auth.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

/***
 * This entity as a model for the database.
 * This is a class used to define the role of a user.
 * Users can have one role, and one role can have multiple permissions.
 * With this a user can access CRUD permissions for some tables in the database.
 *
 *     private Integer id
 *     private String name
 *     private String description
 *     private Integer priority
 *     private List<Permission> rolePermissions
 *
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table (name = "_roles")
public class Role {
    @Id
    private Integer id;
    private String name;
    private String description;
    private Integer priority;

    @ManyToMany(cascade=CascadeType.ALL, fetch = FetchType.EAGER)
    @JoinTable(
            name = "roles_permissions",
            joinColumns = @JoinColumn(name = "role_id"),
            inverseJoinColumns = @JoinColumn(name = "permission_id"))
    private List<Permission> rolePermissions;

    @Transactional
    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities(){
        return this.getRolePermissions().stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getName()))
                .collect(Collectors.toList());
    }
}
