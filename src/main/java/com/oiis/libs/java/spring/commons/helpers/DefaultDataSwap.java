package com.oiis.libs.java.spring.commons.helpers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;

import java.util.Objects;

public class DefaultDataSwap {

    private static final Logger logger = LoggerFactory.getLogger(DefaultDataSwap.class);

    public boolean success = false;
    public Object data = null;
    public String message = null;
    public Integer httpStatusCode = null;
    public Exception exception = null;

    public DefaultDataSwap() {}

    public DefaultDataSwap(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    public void setException(Exception exception) {
        logger.error("parameter error on setException",exception);
        this.httpStatusCode = Objects.requireNonNullElse(this.httpStatusCode, HttpStatus.INTERNAL_SERVER_ERROR.value());
        this.exception = exception;
        if (!StringUtils.hasText(this.message) && this.exception != null) {
            this.message = this.exception.getMessage();
        }
    }

    public ResponseEntity<DefaultDataSwap> sendHttpResponse() {
        return this.success ? ResponseEntity.status(HttpStatus.OK).body(this) : ResponseEntity.status(Objects.requireNonNullElse(this.httpStatusCode, HttpStatus.INTERNAL_SERVER_ERROR.value())).body(this);
    }
}
