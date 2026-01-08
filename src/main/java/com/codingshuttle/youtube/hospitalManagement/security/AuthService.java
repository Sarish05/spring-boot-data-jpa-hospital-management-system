package com.codingshuttle.youtube.hospitalManagement.security;

import com.codingshuttle.youtube.hospitalManagement.dto.LoginRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.LoginResponseDto;
import com.codingshuttle.youtube.hospitalManagement.dto.SignupRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.SignupResponseDto;
import com.codingshuttle.youtube.hospitalManagement.entity.User;
import com.codingshuttle.youtube.hospitalManagement.entity.type.AuthProviderType;
import com.codingshuttle.youtube.hospitalManagement.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.event.GenericApplicationListener;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

//Handles complete Login starting from fetching the user from db to hashing
//password to compare then to returning userDetails object
//User is taken from getPrincipal
//token is created using auth service method
//and token along with userId is returned
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthUtil authUtil;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final UserRepository userRepository;

    public LoginResponseDto login(LoginRequestDto loginRequestDto) {
        //Authentication manager authenticates the user and returned new authentication object
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(),loginRequestDto.getPassword())
        );

        User user = (User) authentication.getPrincipal();    //extract principal from that object
        String token = authUtil.generateAccessToken(user);    // create token for user
        return new LoginResponseDto(token,user.getId());       //return token along with the userId
    }


    //Signup when called from signup Controller
    public SignupResponseDto signup(SignupRequestDto signupRequestDto) {
        //Check if user exists already, if yes then throw exception
        User user = userRepository.findByUsername(signupRequestDto.getUsername()).orElse(null);
        if(user != null) throw new IllegalArgumentException("User already exists!");
        //If not then create one and save in DB
        user = userRepository.save(User
                .builder()
                .username(signupRequestDto.getUsername())
                .password(passwordEncoder.encode(signupRequestDto.getPassword()))
                .providerId(null)                       //as schema changed do this for normal signup
                .providerType(AuthProviderType.EMAIL)   //here also
                .build()
        );
        return new SignupResponseDto(
            user.getId(),
            user.getUsername()
        );
    }

    public User signUpUsingOAuth(SignupRequestDto signupRequestDto, AuthProviderType authProviderType, String authProviderId){
        //Check if user exists already, if yes then throw exception
        User user = userRepository.findByUsername(signupRequestDto.getUsername()).orElse(null);
        if(user != null) throw new IllegalArgumentException("User already exists!");
        //for providers like google it will be null
        String password = null;
        //for email provider it will be encoded
        if(authProviderType == AuthProviderType.EMAIL){
            password= passwordEncoder.encode(signupRequestDto.getPassword());
        }

        //If not then create one and save in DB
        user = userRepository.save(User
                .builder()
                .username(signupRequestDto.getUsername())
                .password(password)
                .providerType(authProviderType)
                .providerId(authProviderId)
                .build()
        );
        return user;
    }

    @Transactional
    public ResponseEntity<LoginResponseDto> handleOAuth2LoginRequest(OAuth2User oAuth2User, String registrationId) {
        //ProviderType and ProviderID
        //Save ProviderID and ProviderType along with user
        //If user already exists, then direct login
        //If not, user signup and then login

        AuthProviderType authProviderType = authUtil.getProviderTypeFromRegistrationId(registrationId);
        String providerId = authUtil.determineProviderFromOAuth2User(oAuth2User, registrationId);

        User user = userRepository.findByProviderIdAndProviderType(providerId, authProviderType).orElse(null);

        //if that provider gives us email we may have usernam with that email
        String email = oAuth2User.getAttribute("email");
        //we will check if the user exists with that email
        User emailUser = userRepository.findByUsername(email).orElse(null);

        //signup flow
        if(user == null && emailUser == null){
            //extract email or else according to each provider type but should not be blank
            String username = authUtil.determineUsernameFromOAuth2User(oAuth2User, registrationId, providerId);
            //then call signup, without password as we dont need
            user = signUpUsingOAuth(new SignupRequestDto(username, null), authProviderType,providerId);

        }
        //if user with provider details already exists then login only
        else if(user!= null){
            //If in case username has been changed for that user with same provider details OR in future you get access to email then
            if(email != null && !email.isBlank() && !email.equals(user.getUsername())){
                user.setUsername(email);
                userRepository.save(user);
            }
        }//this will handle the case in which emailUser is found , which means user trying to login
        // using different provider credentials . we dont want him to do that
        else{
            throw new BadCredentialsException("This email is already registered with " + emailUser.getProviderType());
        }
        //Now send token
        String token = authUtil.generateAccessToken(user);

        LoginResponseDto loginResponseDto = new LoginResponseDto(token, user.getId());

        return ResponseEntity.ok(loginResponseDto);

    }
}
