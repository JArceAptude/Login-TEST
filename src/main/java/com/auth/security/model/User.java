package com.auth.security.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Date;

/***
 * This entity as a model for the database
 *
 *     private Integer id;
 *     private String firstname;
 *     private String lastname;
 *     private String email;
 *     private String password;
 *     private Date lastLogin;
 *     private Date dateJoined;
 *     private Boolean isActive;
 *     private Role role;
 *
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="_user")
public class User implements UserDetails {
    @Id
    private Integer id;
    private String firstname;
    private String lastname;
    @Column(unique=true)
    private String email;
    private String password;
    @Column(name = "last_login")
    private Date lastLogin;
    @Column(name = "date_joined")
    private Date dateJoined;
    @Column(name = "is_active")
    private Boolean isActive;
    @JoinColumn(name = "role")
    @ManyToOne(targetEntity = Role.class, fetch = FetchType.EAGER)
    @JsonIgnore
    private Role role;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return role.getAuthorities();
    }

    @Override
    @JsonIgnore
    public String getUsername() {
        return email;
    }

    @Override
    @JsonIgnore
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    @JsonIgnore
    public boolean isEnabled() {
        return true;
    }
}
