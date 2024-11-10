package com.vic.reservations.Service.implementation;

import com.vic.reservations.Dto.LoginRequest;
import com.vic.reservations.Dto.Response;
import com.vic.reservations.Dto.TokenResponse;
import com.vic.reservations.Dto.UserDto;
import com.vic.reservations.Entity.Token;
import com.vic.reservations.Entity.User;
import com.vic.reservations.Repository.TokenRepository;
import com.vic.reservations.Repository.UserRepository;
import com.vic.reservations.Service.Interfac.IUserInterface;
import com.vic.reservations.Service.JwtService;
import com.vic.reservations.enums.AuthProvider;
import com.vic.reservations.enums.Role;
import com.vic.reservations.exception.MyException;
import com.vic.reservations.utils.Utils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Slf4j
@Service
public class UserService implements IUserInterface {

    private final UserRepository userRepository;

    private final JwtService jwtService;

    private final TokenRepository tokenRepository;

    private final AuthenticationManager authenticationManager;

    private final PasswordEncoder passwordEncoder;

    private final OAuth2AuthorizedClientService authorizedClientService;

    private final Utils utils;



    public UserService(UserRepository userRepository, JwtService jwtService, TokenRepository tokenRepository, AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, OAuth2AuthorizedClientService authorizedClientService, Utils utils) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.tokenRepository = tokenRepository;
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.authorizedClientService = authorizedClientService;
        this.utils = utils;
    }

    public Response registerUserLocally(User user) {

        Response response = new Response();

        try {
            if (user.getRole() == null) {
                user.setRole(Role.USER);
            }
            System.out.println(user.getRole());
            if (userRepository.existsByEmail(user.getEmail())) {
                throw new MyException(user.getEmail() + "Already Exists");
            }


            user.setFirstName(user.getFirstName());
            user.setLastName(user.getLastName());
            user.setEmail(user.getEmail());
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user.setAuthProvider(AuthProvider.LOCAL);

            User savedUser = userRepository.save(user);

            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            saveUserToken(accessToken, refreshToken, user);

            UserDto userDto = Utils.mapUserEntityToUserDTO(savedUser);
            response.setStatusCode(200);
            response.setUser(userDto);
        } catch (MyException e) {
            response.setStatusCode(400);
            response.setMessage(e.getMessage());
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error Occurred During User Registration " + e.getMessage());

        }
        return response;
    }

    @Override
    public Response registerOrLoginUserWithGoogle(OAuth2AuthenticationToken auth2AuthenticationToken, HttpServletRequest request) {
        Response response = new Response();
        try {
            if (auth2AuthenticationToken == null) {
                log.error("OAuth2AuthenticationToken is null");
                response.setStatusCode(400);
                response.setMessage("OAuth2AuthenticationToken is null");
                return response;
            }
            OAuth2User oAuth2User = auth2AuthenticationToken.getPrincipal();
            System.out.println(auth2AuthenticationToken);
            String email = oAuth2User.getAttribute("email");

            String firstName = oAuth2User.getAttribute("given_name");
            String lastName = oAuth2User.getAttribute("family_name");

            log.info("USER Email FROM GOOGLE IS {}", email);
            log.info("USER first name from GOOGLE IS {}", firstName);
            log.info("USER last name from GOOGLE IS {}", lastName);

            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                    auth2AuthenticationToken.getAuthorizedClientRegistrationId(), auth2AuthenticationToken.getName());
            OAuth2AccessToken oAuth2AccessToken = authorizedClient.getAccessToken();
            log.info("Access Token: {}", oAuth2AccessToken.getTokenValue());

            User user = userRepository.findByEmail(email).orElse(null);
            if (user == null) {
                user = new User();
                user.setFirstName(firstName);
                user.setLastName(lastName);
                user.setEmail(email);
                user.setAuthProvider(AuthProvider.GOOGLE);
                user.setRole(Role.USER);
            }

            User savedUser = userRepository.save(user);
            UserDto userDto = Utils.mapUserEntityToUserDTO(savedUser);
            response.setAccessToken(oAuth2AccessToken.getTokenValue());
            response.setExpirationTime("1 hour");
            response.setStatusCode(200);
            response.setUser(userDto);

        } catch (MyException e) {
            response.setStatusCode(400);
            response.setMessage(e.getMessage());
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error Occurred During User Registration with google " + e.getMessage());
        }
        return response;
    }


//    @Override
//    public Response registerOrLoginUserWithGoogle(OAuth2AuthenticationToken auth2AuthenticationToken, HttpServletRequest request) {
//        Response response = new Response();
//        try {
//            if (auth2AuthenticationToken == null) {
//                log.error("OAuth2AuthenticationToken is null");
//                return null;
//            }
//            OAuth2User oAuth2User = auth2AuthenticationToken.getPrincipal();
//            System.out.println(auth2AuthenticationToken);
//            String email = oAuth2User.getAttribute("email");
//
//            String firstName = oAuth2User.getAttribute("given_name");
//            String lastName = oAuth2User.getAttribute("family_name");
//
//            log.info("USER Email FROM GOOGLE IS {}", email);
//            log.info("USER first name from GOOGLE IS {}", firstName);
//            log.info("USER last name from GOOGLE IS {}", lastName);
//
//            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
//                    auth2AuthenticationToken.getAuthorizedClientRegistrationId(), auth2AuthenticationToken.getName());
//            OAuth2AccessToken oAuth2AccessToken = authorizedClient.getAccessToken();
//            log.info("Access Token: {}", oAuth2AccessToken.getTokenValue());
//
//            User user = userRepository.findByEmail(email).orElse(null);
//            if (user == null) {
//                user = new User();
//                user.setFirstName(firstName);
//                user.setLastName(lastName);
//                user.setEmail(email);
//                user.setAuthProvider(AuthProvider.GOOGLE);
//                user.setOauthAccessToken(oAuth2AccessToken.getTokenValue());
//                user.setRole(Role.USER);
//            } else {
//                user.setOauthAccessToken(oAuth2AccessToken.getTokenValue());
//            }
//            String accessToken = jwtService.generateAccessToken(user);
//            System.out.println(accessToken);
//            String refreshToken = jwtService.generateRefreshToken(user);
//            System.out.println(refreshToken);
//            User savedUser = userRepository.save(user);
//            UserDto userDto = Utils.mapUserEntityToUserDTO(savedUser);
//            response.setOAuthAccessToken(oAuth2AccessToken.getTokenValue());
//            response.setAccessToken(accessToken);
//            response.setRefreshToken(refreshToken);
//            response.setExpirationTime("7 Days");
//            response.setStatusCode(200);
//            response.setUser(userDto);
//
//        } catch (MyException e) {
//            response.setStatusCode(400);
//            response.setMessage(e.getMessage());
//        } catch (Exception e) {
//            response.setStatusCode(500);
//            response.setMessage("Error Occurred During User Registration with google " + e.getMessage());
//        }
//        return response;
//    }


//    @Override
//    public Response registerOrLoginUserWithGoogle(OAuth2AuthenticationToken auth2AuthenticationToken, HttpServletRequest request) {
//        Response response = new Response();
//        try {
//            if (auth2AuthenticationToken == null) {
//                log.error("OAuth2AuthenticationToken is null");
//                return null;
//            }
//            OAuth2User oAuth2User = auth2AuthenticationToken.getPrincipal();
//            System.out.println(auth2AuthenticationToken);
//            String email = oAuth2User.getAttribute("email");
//
//            String firstName = oAuth2User.getAttribute("given_name");
//            String lastName = oAuth2User.getAttribute("family_name");
//
//            log.info("USER Email FROM GOOGLE IS {}", email);
//            log.info("USER first name from GOOGLE IS {}", firstName);
//            log.info("USER last name from GOOGLE IS {}", lastName);
//
//            OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
//                    auth2AuthenticationToken.getAuthorizedClientRegistrationId(), auth2AuthenticationToken.getName() );
//            OAuth2AccessToken oAuth2AccessToken = authorizedClient.getAccessToken();
//            log.info("Access Token: {}", oAuth2AccessToken.getTokenValue());
//
//            User user = userRepository.findByEmail(email).orElse(null);
//            if (user == null) {
//                user = new User();
//                user.setFirstName(firstName);
//                user.setLastName(lastName);
//                user.setEmail(email);
//                user.setAuthProvider(AuthProvider.GOOGLE);
//                user.setOauthAccessToken(String.valueOf(oAuth2AccessToken));
//                user.setRole(Role.USER);
//            } else {
//
//                user.setOauthAccessToken(String.valueOf(oAuth2AccessToken));
//            }
//                String accessToken = jwtService.generateAccessToken(user);
//            System.out.println(accessToken);
//                String refreshToken = jwtService.generateRefreshToken(user);
//            System.out.println(refreshToken);
//                User savedUser = userRepository.save(user);
//                UserDto userDto = Utils.mapUserEntityToUserDTO(savedUser);
//                response.setOAuthAccessToken(String.valueOf(oAuth2AccessToken));
//                response.setAccessToken(accessToken);
//                response.setRefreshToken(refreshToken);
//                response.setExpirationTime("7 Days");
//                response.setStatusCode(200);
//                response.setUser(userDto);
//
//        }catch (MyException e) {
//            response.setStatusCode(400);
//            response.setMessage(e.getMessage());
//        } catch (Exception e) {
//            response.setStatusCode(500);
//            response.setMessage("Error Occurred During User Registration with google " + e.getMessage());
//
//        }
//        return response;
//    }

    public Response loginUserLocally(LoginRequest loginRequest) {
        System.out.println("started");
        Response response = new Response();
        try {
             authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );
            System.out.println(loginRequest.getEmail());
            System.out.println(loginRequest.getPassword());
            User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(() -> new MyException("User does not exist"));
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            revokeAllTokenByUser(user);
            saveUserToken(accessToken, refreshToken, user);
            response.setStatusCode(200);
            response.setAccessToken(accessToken);
            response.setRefreshToken(refreshToken);
            response.setExpirationTime("7 Days");
            response.setMessage("successful");
            System.out.println(response);
        } catch (MyException e) {
            response.setStatusCode(404);
            response.setMessage(e.getMessage());

        } catch (Exception e) {

            response.setStatusCode(500);
            response.setMessage("Error Occurred During User Login " + e.getMessage());
        }
        return response;
    }

    @Override
    public Response getAllUsers() {
        Response response = new Response();
        try {
            List<User> userList = userRepository.findAll();
            List<UserDto> userDTOList = Utils.mapUserListEntityToUserListDTO(userList);
            response.setStatusCode(200);
            response.setMessage("successful");
            response.setUserList(userDTOList);

        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error getting all users " + e.getMessage());
        }
        return response;
    }

    @Override
    public Response getUserReservations(String userId) {

        Response response = new Response();

        try {
            UUID uuid = UUID.fromString(userId); // Ensure valid UUID
            User user = userRepository.findById(uuid).orElseThrow(() -> new MyException("User Not Found"));
            UserDto userDto = Utils.mapUserEntityToUserDTOPlusReservations(user);
            response.setStatusCode(200);
            response.setMessage("successful");
            response.setUser(userDto);

        } catch (MyException e) {
            response.setStatusCode(404);
            response.setMessage(e.getMessage());

        } catch (Exception e) {

            response.setStatusCode(500);
            response.setMessage("Error getting all users " + e.getMessage());
        }
        return response;
    }

    @Override
    public Response deleteUser(String userId) {
        Response response = new Response();

        try {
            UUID uuid = UUID.fromString(userId); // Ensure valid UUID
            User user = userRepository.findById(uuid).orElseThrow(() -> new MyException("User Not Found"));
            userRepository.deleteById(uuid);
            response.setStatusCode(200);
            response.setMessage("successful");

        } catch (MyException e) {
            response.setStatusCode(404);
            response.setMessage(e.getMessage());

        } catch (Exception e) {

            response.setStatusCode(500);
            response.setMessage("Error getting all user " + e.getMessage());
        }
        return response;
    }

    @Override
    public Response getUserById(String userId) {
        Response response = new Response();
        try {
            UUID uuid = UUID.fromString(userId); // Ensure valid UUID
            User user = userRepository.findById(uuid).orElseThrow(() -> new MyException("User Not Found"));
        UserDto userDTO = Utils.mapUserEntityToUserDTO(user);
        response.setStatusCode(200);
        response.setMessage("successful");
        response.setUser(userDTO);
    } catch (IllegalArgumentException e) {
        response.setStatusCode(400);
        response.setMessage("Invalid UUID format: " + userId);
    } catch (MyException e) {
        response.setStatusCode(404);
        response.setMessage(e.getMessage());
    } catch (Exception e) {
        response.setStatusCode(500);
        response.setMessage("Error getting user: " + e.getMessage());
    }
        return response;
    }

    @Override
    public Response getMyInfo(String email) {

        Response response = new Response();

        try {
            User user = userRepository.findByEmail(email).orElseThrow(() -> new MyException("User Not Found"));
            UserDto userDTO = Utils.mapUserEntityToUserDTO(user);
            response.setStatusCode(200);
            response.setMessage("successful");
            response.setUser(userDTO);

        } catch (MyException e) {
            response.setStatusCode(404);
            response.setMessage(e.getMessage());

        } catch (Exception e) {

            response.setStatusCode(500);
            response.setMessage("Error getting all users " + e.getMessage());
        }
        return response;
    }

    private void revokeAllTokenByUser(User user) {
        List<Token> validTokens = tokenRepository.findAllAccessTokensByUser(user.getId());
        if(validTokens.isEmpty()) {
            return;
        }

        validTokens.forEach(t-> {
            t.setLoggedOut(true);
        });

        tokenRepository.saveAll(validTokens);
    }

    private void saveUserToken(String accessToken, String refreshToken, User user) {
        Token token = new Token();
        token.setAccessToken(accessToken);
        token.setRefreshToken(refreshToken);
        token.setLoggedOut(false);
        token.setUser(user);
        tokenRepository.save(token);
    }

    public ResponseEntity refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {



            // extract the token from authorization header
            String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return new ResponseEntity(HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);

            // extract username from token
            String email = jwtService.extractUsername(token);

            // check if the user exist in database
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("No user found"));

            // check if the token is valid
            if (jwtService.isValidRefreshToken(token, user)) {
                // generate access token
                String accessToken = jwtService.generateAccessToken(user);
                String refreshToken = jwtService.generateRefreshToken(user);

                revokeAllTokenByUser(user);
                saveUserToken(accessToken, refreshToken, user);

                return new ResponseEntity(new TokenResponse( accessToken,refreshToken,"New token generated"), HttpStatus.OK );
            }

            return new ResponseEntity(HttpStatus.UNAUTHORIZED);
        }

//    @Override
//    public Response verifyLoggedInUserWithGoogle(OAuth2AuthenticationToken auth2AuthenticationToken) {
//        Response response = new Response();
//        try {
//            if (auth2AuthenticationToken == null) {
//                log.error("OAuth2AuthenticationToken is null");
//                return null;
//            }
//            OAuth2User oAuth2User = auth2AuthenticationToken.getPrincipal();
//            String email = oAuth2User.getAttribute("email");
//            String firstName = oAuth2User.getAttribute("given_name");
//            String lastName = oAuth2User.getAttribute("family_name");
//
//            log.info("USER Email FROM GOOGLE IS {}", email);
//            log.info("USER first name from GOOGLE IS {}", firstName);
//            log.info("USER last name from GOOGLE IS {}", lastName);
//
//            User user = userRepository.findByEmail(email).orElse(null);
//            if (user != null) {
//                UserDto userDto = Utils.mapUserEntityToUserDTO(user);
//                response.setAccessToken(String.valueOf(auth2AuthenticationToken));
//                response.setStatusCode(200);
//                response.setUser(userDto);
//            } else {
//                response.setStatusCode(404);
//                response.setMessage("User not found");
//            }
//        } catch (MyException e) {
//            response.setStatusCode(400);
//            response.setMessage(e.getMessage());
//        } catch (Exception e) {
//            response.setStatusCode(500);
//            response.setMessage("Error Occurred During User verification with Google " + e.getMessage());
//        }
//        return response;
//    }



}

