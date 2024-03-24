package com.domainizer.administration.repository;

import com.domainizer.administration.model.UserData;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface UserRepository extends JpaRepository<UserData, Long> {

    @Query("SELECT u.password FROM UserData u WHERE u.username = :username")
    String findPasswordByUsername(@Param("username") String username);

    UserData findOneByUsername(String username);

    UserData findOneByEmail(String email);
}
