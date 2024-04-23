package io.dev.loginapi.mapper;

import io.dev.loginapi.model.User;
import io.dev.loginapi.rest.dto.UserDto;

public interface UserMapper {

    UserDto toUserDto(User user);
}