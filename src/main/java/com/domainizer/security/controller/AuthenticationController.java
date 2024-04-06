package com.domainizer.security.controller;

import com.domainizer.administration.model.UserData;
import com.domainizer.administration.repository.UserRepository;
import com.domainizer.security.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/authentication")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final UserRepository userRepository;

    @Autowired
    public AuthenticationController(
            AuthenticationService authenticationService,
            UserRepository userRepository) {
        this.authenticationService = authenticationService;
        this.userRepository = userRepository;
    }

    @PostMapping("/authenticateUser")
    public ResponseEntity<Map<String, String>> authenticateUser(@RequestBody Map<String, String> userDataMap) {
        String username = userDataMap.get("username");
        String password = userDataMap.get("password");

        if (authenticationService.isValidAuthenticationData(username, password)) {
            UserData user = userRepository.findOneByUsername(username);
            String token = authenticationService.authenticateUser(user);

            Map<String, String> response = new HashMap<>();
            response.put("token", token);
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(401).build();
    }
}
