package com.domainizer.administration.controller;

import com.domainizer.administration.model.UserData;
import com.domainizer.administration.model.UserRole;
import com.domainizer.administration.service.UserService;
import com.domainizer.exceptions.EmailTakenException;
import com.domainizer.exceptions.UsernameTakenException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/administration")
public class UserController {

    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/user")
    public ResponseEntity<List<UserData>> getUsers() {
        return ResponseEntity.ok(userService.getUsers());
    }

    @PostMapping("/user")
    public ResponseEntity<UserData> createUser(@RequestBody Map<String, String> userDataJson) throws UsernameTakenException, EmailTakenException {
        // Function should take User object as argument, but I have problem with handling password (it is visible
        // when returning User object, when using @JsonIgnore on password field, it is being ignored when saving to DB)
        String username = userDataJson.get("username");
        String password = userDataJson.get("password");
        String email = userDataJson.get("email");
        UserRole role = UserRole.USER;
        if ("Administrator".equals(userDataJson.get("role"))) {
            role = UserRole.ADMINISTRATOR;
        }
        UserData newUser = new UserData(username, password, email, role);

        return ResponseEntity.ok(userService.createUser(newUser));
    }

    @DeleteMapping("/user/{userId}")
    public ResponseEntity<Void> deleteUser(@PathVariable Long userId) {
        userService.deleteUser(userId);
        return ResponseEntity.ok().build();
    }
}
