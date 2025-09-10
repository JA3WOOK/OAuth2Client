package com.jaewook.oauth2client.controller;

import com.jaewook.oauth2client.entity.User;
import com.jaewook.oauth2client.repository.UserRepository;
import com.jaewook.oauth2client.security.dto.UserResponseDto;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api")
public class AuthController {

    private final UserRepository userRepository;

    @GetMapping("/public/login-url")
    public ResponseEntity<Map<String, String>> getLoginUrl() {
        Map<String, String> response = new HashMap<>();
        response.put("googleLoginUrl", "/oauth2/authorization/google");
        response.put("githubLoginUrl", "/oauth2/authorization/github");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user/info")
    public ResponseEntity<UserResponseDto> getUserInfo() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new RuntimeException("인증되지 않은 사용자입니다.");
        }

        String email = authentication.getName();
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("사용자를 찾을 수 없습니다."));

        return ResponseEntity.ok(new UserResponseDto(user));
    }

}
