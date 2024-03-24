package com.domainizer.exceptions;

public class EmailTakenException extends Exception {
    public EmailTakenException(String message, String email) {
        super(message);
    }
}
