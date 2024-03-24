package com.domainizer.security.service;

import com.domainizer.administration.model.UserData;
import com.domainizer.administration.repository.UserRepository;
import com.domainizer.security.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final PasswordService passwordService;
    private final UserRepository userRepository;
    private final JwtProvider jwtProvider;

    @Autowired
    public AuthenticationService(
            PasswordService passwordService,
            UserRepository userRepository,
            JwtProvider jwtProvider) {
        this.passwordService = passwordService;
        this.userRepository = userRepository;
        this.jwtProvider = jwtProvider;
    }

    public String authenticateUser(UserData user) {
        return jwtProvider.generateToken(user);
    }

    public boolean isValidAuthenticationData(String username, String loginPassword) {
        String userPassword = userRepository.findPasswordByUsername(username);
        if (userPassword != null) {
            return passwordService.validatePassword(loginPassword, userPassword);
        }
        return false;
    }
}
