package com.jaewook.oauth2client.security.dto;

import com.jaewook.oauth2client.entity.User;
import lombok.Getter;

@Getter
public class UserResponseDto {
    private final Long id;
    private final String provider;
    private final String name;
    private final String email;
    private final String picture;

    public UserResponseDto(User user) {
        this.id = user.getId();
        this.provider = user.getProvider().name();
        this.name = user.getName();
        this.email = user.getEmail();
        this.picture = user.getPicture();
    }
}

