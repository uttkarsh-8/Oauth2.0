package com.oath2.oath20.controller;

import com.oath2.oath20.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("sign-in")
    public ResponseEntity<?> authenticateUser(Authentication authentication){

        return ResponseEntity.ok(authService.getJwtTokensAfterAuthentication(authentication));
    }
}
