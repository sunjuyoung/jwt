package com.example.security.config;

import com.example.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository repository;
    @Bean
    public UserDetailsService userDetailsService() {
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }


    /*
    * AbstractUserDetailsAuthenticationProvider를 상속받은 클래스 DaoAuthenticationProvider
    DaoAuthenticationProvider에서 재정의된 메소드중 봐야할 것이 additionalAuthenticationChecks()와 retrieveUser()이다.
    retrieveUser()는 UserDetailsService객체를 통해 로그인 요청한 유저의 UserDetails 객체를 가져온다
    additionalAuthenticationChecks()메소드는 입력받은 정보(username, credetial)와 userDetails객체의
    정보와 비교해 인증을 체크하는 메소드이다. 실질적으로 DB의 데이터와 id, 비밀번호를 입력한 값과 비교하는 곳이라 할 수 있다.
    메소드를 이용해서 사용자 id와 비밀번호가 맞다는 것을 판별하면 AbstractDetailsAuthenticationProvider의 authenticate()의
    마지막 부분에 createSuccessAuthentication(principalToReturn, authentication, user)가 반환된다.
    UsernamePasswordAuthenticationToken객체를 만드는걸 볼 수 있다
    *
    * */
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
