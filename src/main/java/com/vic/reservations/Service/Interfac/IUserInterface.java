package com.vic.reservations.Service.Interfac;

import com.vic.reservations.Dto.LoginRequest;
import com.vic.reservations.Dto.Response;
import com.vic.reservations.Entity.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

public interface IUserInterface {

    Response registerUserLocally(User user);

    Response registerOrLoginUserWithGoogle(OAuth2AuthenticationToken auth2AuthenticationToken, HttpServletRequest request);

    Response loginUserLocally(LoginRequest loginRequest);

    Response getAllUsers();

    Response getUserReservations(String userId);

    Response deleteUser(String userId);

    Response getUserById(String userId);

    Response getMyInfo(String email);

//    Response verifyLoggedInUserWithGoogle(OAuth2AuthenticationToken auth2AuthenticationToken);
}
