package com.domainizer.administration.service;

import com.domainizer.administration.model.UserData;
import com.domainizer.administration.repository.UserRepository;
import com.domainizer.exceptions.EmailTakenException;
import com.domainizer.exceptions.UsernameTakenException;
import com.domainizer.security.service.PasswordService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    static Logger logger = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;
    private final PasswordService passwordService;

    @Autowired
    public UserService(UserRepository userRepository, PasswordService passwordService) {
        this.userRepository = userRepository;
        this.passwordService = passwordService;
    }

    public List<UserData> getUsers() {
        return userRepository.findAll();
    }

    public void deleteUser(Long userId) {
        userRepository.deleteById(userId);
    }

    public UserData createUser(UserData newUserData) throws UsernameTakenException, EmailTakenException {
        if (isUsernameTaken(newUserData.getUsername())) {
            logger.warn(String.format("Username %s is already taken", newUserData.getUsername()));
            throw new UsernameTakenException(String.format("Username %s is already taken", newUserData.getUsername()));
        }
        if (isEmailTaken(newUserData.getEmail())) {
            logger.warn(String.format("Email %s is already taken", newUserData.getEmail()));
            throw new EmailTakenException("Email %s is already taken", newUserData.getEmail());
        }
        String hashedPassword = passwordService.generatePasswordHash(newUserData.getPassword());
        newUserData.setPassword(hashedPassword);
        userRepository.save(newUserData);
        return newUserData;
    }

    private boolean isUsernameTaken(String username) {
        return userRepository.findOneByUsername(username) != null;
    }

    private boolean isEmailTaken(String email) {
        return userRepository.findOneByEmail(email) != null;
    }

}
