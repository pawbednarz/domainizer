package com.domainizer.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class Http500Handler {

    static Logger log = LoggerFactory.getLogger(Http500Handler.class);
    private final String ERROR_MESSAGE = "Something went wrong. Please, try again later or contact your Administrator.";

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(Exception.class)
    public ResponseEntity handle500(HttpServletRequest request, Exception e) {
        Map<String, String> error = new HashMap<>();
        error.put("error", ERROR_MESSAGE);
        log.error("HTTP 500 Internal Server Error. Message - " + e.getMessage() + "\n" + Arrays.toString(e.getStackTrace()));
        return ResponseEntity.status(500).body(error);
    }
}
