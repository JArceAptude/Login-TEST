package com.auth.security.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/***
 * This entity as a model for the database
 * This is the permission's class.
 * Is used to give user specific permissions for the different CRUDs
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@JsonIgnoreProperties("roles")
@Table(name="_permissions")
public class Permission {

    @Id
    private Integer id;

    @Column(unique = true)
    private String name;
    private String description;

    @ManyToMany(mappedBy = "rolePermissions")
    private List<Role> roles;

}
