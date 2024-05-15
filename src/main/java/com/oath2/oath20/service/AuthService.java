package com.oath2.oath20.service;

import com.oath2.oath20.dto.AuthResponseDto;
import com.oath2.oath20.dto.TokenType;
import com.oath2.oath20.repository.UserInfoRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.security.core.Authentication;
import org.springframework.web.server.ResponseStatusException;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserInfoRepository userInfoRepository;
    private final JwtTokenGenerator jwtTokenGenerator;

    public AuthResponseDto getJwtTokensAfterAuthentication(Authentication auhthentication){
        try {
            var userInfoEntity = userInfoRepository.findByEmailId(auhthentication.getName()).orElseThrow(()-> new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND"));

            String accessToken = jwtTokenGenerator.generateAccessToken(auhthentication);

            return AuthResponseDto.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(15*60)
                    .username(userInfoEntity.getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();

        }catch (Exception e){
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please try again!! the error might be: " + e.getMessage());
        }
    }
}
