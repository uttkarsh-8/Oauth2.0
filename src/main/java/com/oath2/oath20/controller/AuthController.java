package com.oath2.oath20.controller;

import com.oath2.oath20.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.core.Authentication;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("sign-in")
    public ResponseEntity<?> authenticateUser(Authentication auhtentication){

        return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication(authentication));
    }
}
