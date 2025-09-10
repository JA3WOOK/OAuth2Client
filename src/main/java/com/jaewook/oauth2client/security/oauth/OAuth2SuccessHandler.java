package com.jaewook.oauth2client.security.oauth;

import com.jaewook.oauth2client.entity.User;
import com.jaewook.oauth2client.security.dto.CustomOAuth2User;
import com.jaewook.oauth2client.security.dto.UserResponseDto;
import com.jaewook.oauth2client.security.jwt.JwtTokenProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();

        // 사용자 조회만 수행 (저장하지 않음)
        User user = oAuth2User.getUser();

        // JWT 토큰 생성
        String token = jwtTokenProvider.createToken(user.getEmail(), user.getRoleKey());

        // 응답 생성
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("token", token);
        responseData.put("user", new UserResponseDto(user));

        response.getWriter().write(objectMapper.writeValueAsString(responseData));
    }

}