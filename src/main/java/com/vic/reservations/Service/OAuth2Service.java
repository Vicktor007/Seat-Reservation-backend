package com.vic.reservations.Service;

import com.vic.reservations.Dto.Response;
import com.vic.reservations.Entity.User;
import com.vic.reservations.Repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@Slf4j
@RequiredArgsConstructor
public class OAuth2Service {

    private final UserRepository userRepository;

    private final JwtService jwtService;

    public Response verifyGoogleToken(String token) {
        Response response = new Response();
        try {
            String url = "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + token;
            RestTemplate restTemplate = new RestTemplate();
            GoogleTokenInfo tokenInfo = restTemplate.getForObject(url, GoogleTokenInfo.class);
            String Expires_in = tokenInfo.getExpires_in();
            System.out.println(Expires_in);
            String verifiedEmail = tokenInfo.getEmail_verified();
            System.out.println(verifiedEmail);


            if (tokenInfo != null && tokenInfo.getEmail() != null) {
                User user = userRepository.findByEmail(tokenInfo.getEmail()).orElse(null);
                if (user != null) {




                 String accessToken = token;
                    System.out.println(accessToken);
                    response.setStatusCode(200);
                    response.setMessage("Token is valid");
                    response.setRole(String.valueOf(user.getRole()));
                    response.setAccessToken(accessToken);
                    response.setAuthProvider(String.valueOf(user.getAuthProvider()));
                    System.out.println(user.getAuthProvider());
                } else {
                    response.setStatusCode(404);
                    response.setMessage("User not found");
                }
            } else {
                response.setStatusCode(401);
                response.setMessage("Invalid token");
            }
        } catch (Exception e) {
            response.setStatusCode(500);
            response.setMessage("Error occurred during token verification: " + e.getMessage());
        }
        return response;
    }

    // Inner class to map the token info response
    public static class GoogleTokenInfo {
        private String email;

        private String expires_in;

        private String email_verified;

        // Getters and setters
        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }



        public String getExpires_in() {
            return expires_in;
        }

        public void setExpires_in(String expires_in) {
            this.expires_in = expires_in;
        }


        public String getEmail_verified() {
            return email_verified;
        }

        public void setEmail_verified(String email_verified) {
            this.email_verified = email_verified;
        }


    }
}
