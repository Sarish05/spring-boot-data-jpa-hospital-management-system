package com.codingshuttle.youtube.hospitalManagement.security;

import com.codingshuttle.youtube.hospitalManagement.dto.LoginRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.LoginResponseDto;
import com.codingshuttle.youtube.hospitalManagement.dto.SignupRequestDto;
import com.codingshuttle.youtube.hospitalManagement.dto.SignupResponseDto;
import com.codingshuttle.youtube.hospitalManagement.entity.User;
import com.codingshuttle.youtube.hospitalManagement.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

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

    public SignupResponseDto signup(SignupRequestDto signupRequestDto) {
        //Check if user exists already, if yes then throw exception
        User user = userRepository.findByUsername(signupRequestDto.getUsername()).orElse(null);
        if(user != null) throw new IllegalArgumentException("User already exists!");
        //If not then create one and save in DB
        user = userRepository.save(User
                .builder()
                .username(signupRequestDto.getUsername())
                .password(passwordEncoder.encode(signupRequestDto.getPassword()))
                .build()
        );

        return new SignupResponseDto(
            user.getId(),
            user.getUsername()
        );
    }


}
