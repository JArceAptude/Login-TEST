package com.auth.security.model.service;

import com.auth.security.authentication.RegisterRequest;
import com.auth.security.model.ResponseObject;
import com.auth.security.model.User;
import com.auth.security.model.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    @Autowired
    private final UserRepository userRepository;

    public List<Optional> getAllActiveUsers(){
        return Collections.singletonList(userRepository.findAllByIsActive(true));
    }

    public ResponseObject getById(Integer id){
        try {
            return new ResponseObject(Optional.of(userRepository.findById(id).get()), "");
        } catch (NoSuchElementException nSEE){
            return new ResponseObject(null, nSEE.getMessage());
        }
    }

    public ResponseObject getByUsername(String email){
        try {
            return new ResponseObject(Optional.of(userRepository.findByEmail(email).get()), "");
        } catch (NoSuchElementException nSEE){
            return new ResponseObject(null, nSEE.getMessage());
        }
    }

    public User updateUserById(Integer id, RegisterRequest request) {

        User thisUser = userRepository.findByEmail(
                SecurityContextHolder.getContext().getAuthentication().getName()
        ).orElseThrow();
        User userToUpdate = userRepository.findById(id).orElseThrow();

        return null;
    }
}
