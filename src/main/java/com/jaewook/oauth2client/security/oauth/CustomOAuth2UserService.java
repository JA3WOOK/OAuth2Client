package com.jaewook.oauth2client.security.oauth;

import com.jaewook.oauth2client.entity.AuthProvider;
import com.jaewook.oauth2client.entity.Role;
import com.jaewook.oauth2client.entity.User;
import com.jaewook.oauth2client.repository.UserRepository;
import com.jaewook.oauth2client.security.dto.CustomOAuth2User;
import com.jaewook.oauth2client.security.dto.OAuthAttributes;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
@RequiredArgsConstructor
@Slf4j
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate = new DefaultOAuth2UserService();
        OAuth2User oAuth2User = delegate.loadUser(userRequest);

        // 현재 로그인 진행 중인 서비스를 구분
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.debug("서비스 registrationId = {}", registrationId);

        // OAuth2 로그인 진행 시 키가 되는 필드값 (PK)
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();
        log.debug("userNameAttributeName = {}", userNameAttributeName);

        // OAuth2UserService를 통해 가져온 데이터를 담을 클래스
        OAuthAttributes attributes = OAuthAttributes.of(registrationId, userNameAttributeName, oAuth2User.getAttributes());

        // 속성 유효성 검사 강화
        validateAttributes(attributes);

        // 사용자 정보 저장 또는 업데이트
        User user = saveOrUpdate(registrationId, attributes);

        return new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRoleKey())),
                attributes.attributes(),
                attributes.nameAttributeKey(),
                user
        );
    }

    // 속성 유효성 검사 메소드 추가
    private void validateAttributes(OAuthAttributes attributes) {
        if (attributes == null) {
            throw new OAuth2AuthenticationException("Invalid OAuth2 user attributes");
        }
        if (attributes.email() == null || attributes.email().isEmpty()) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }
        if (attributes.name() == null || attributes.name().isEmpty()) {
            log.warn("사용자 이름이 OAuth 제공자로부터 제공되지 않았습니다. 이메일로 대체합니다.");
        }
    }

    // 사용자 정보 저장 또는 업데이트
    private User saveOrUpdate(String registrationId, OAuthAttributes attributes) {
        User user = userRepository.findByEmail(attributes.email())
                .map(entity -> entity.update(attributes.name(), attributes.picture()))
                .orElse(User.builder()
                        .name(attributes.name())
                        .email(attributes.email())
                        .picture(attributes.picture())
                        .provider(convertToAuthProvider(registrationId))
                        .role(Role.USER)  // 기본 권한 USER
                        .build());
        return userRepository.save(user);
    }

    private AuthProvider convertToAuthProvider(String registrationId) {
        if ("google".equals(registrationId)) {
            return AuthProvider.GOOGLE;
        } else if ("naver".equals(registrationId)) {
            return AuthProvider.NAVER;
        } else if ("kakao".equals(registrationId)) {
            return AuthProvider.KAKAO;
        } else if ("github".equals(registrationId)) {
            return AuthProvider.GITHUB;
        }
        throw new IllegalArgumentException("Unsupported registrationId: " + registrationId);
    }

}
