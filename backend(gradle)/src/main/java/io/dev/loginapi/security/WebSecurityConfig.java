package io.dev.loginapi.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
// 스프링 시큐리티 3.x 버전부터는 SecurityFilterChain을 람다식으로 작성해야 된다. 그래서 다른 사람들이 써놓은 것들이 안맞을 경우가 많다.
public class WebSecurityConfig {

    private final TokenAuthenticationFilter tokenAuthenticationFilter;

    public static final String ADMIN = "ADMIN";
    public static final String USER = "USER";


    // AuthenticationManager는 스프링 시큐리티에서 인증을 처리하는 핵심 인터페이스입니다.
    // 해당 메서드는 AuthenticationConfiguration 객체를 인자로 받고 이를 사용하여 AuthenticationManager를 생성합니다.
    // 이 메서드는 AuthenticationManager를 반환하고, 이를 통해 스프링 시큐리티에서 인증 관련 작업을 수행할 수 있습니다
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    // 해당 메서드는 HttpSecurity 객체를 인자로 받고, 이를 사용하여 보안 필터 체인을 구성합니다
    // HttpSecurity 는 HTTP 보안을 구성하는 핵심 클래스이다. 일반적으로 spring Security 설정에 사용된다.
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // HTTP 보안 설정 시작
        return http
                // 요청에 대한 인가(허가) 규칙을 설정합니다.
                .authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        // POST /api/orders와 GET /api/users/me 요청 url에 대한 ADMIN 또는 USER 권한이 필요하다.
                        .requestMatchers(HttpMethod.POST, "/api/orders").hasAnyAuthority(ADMIN, USER)
                        .requestMatchers(HttpMethod.GET, "/api/users/me").hasAnyAuthority(ADMIN, USER)
                        // /api/orders와 하위 경로에 대해 ADMIN 권한이 필요하다.
                        .requestMatchers("/api/orders", "/api/orders/**").hasAuthority(ADMIN)
                        // /api/users와 하위 경로에 대해 ADMIN 권한이 필요하다.
                        .requestMatchers("/api/users", "/api/users/**").hasAuthority(ADMIN)
                        // /public/** 및 /auth/** 경로에 대한 모든 요청은 허용된다.
                        .requestMatchers("/public/**", "/auth/**", "/h2-console/**").permitAll()
                        // 기타 모든 요청은 인증이 필요하다.
                        .anyRequest().authenticated())

                // addFilterBefore()는 두개의 인자를 받는다. 첫 번째는 추가할 필터이고 두 번째는 이 필터를 추가할 기존 필터의 클래스
                // 스프링 시큐리티는 tokenAuthenticationFilter를 통해 사용자가 제공하는 토큰 값을 먼저 확인하고 그 다음
                // UsernamePasswordAuthenticationFilter를 통해 사용자가 제공한 사용자 이름 비밀번호를 확인할 수 있다.
                // 이 코드의 목적은 특정한 인증 방식(JWT)을 사용하기 위해 UsernamePasswordAuthenticationFilter 보다
                // 먼저 실행되는 tokenAuthenticationFilter를 필터 체인에 추가하는 것입니다. 이렇게 함으로써 토큰 기반 인증이나 다른 인증 방식을 사용할 수 있다.
                .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

                // exceptionHandling() 메서드는 인증되지 않은 요청에 대한 예외 처리를 한다.
                // authenticationEntryPoint() 메서드를 사용하여 인증되지 않은 요청에 대한 응답을 HTTP 401(Unauthorized)을 반환
                .exceptionHandling(exceptionHandling -> exceptionHandling.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))

                // sessionManagement() 메서드는 세션 관리에 대한 설정을 지정한다.
                // sessionCreationPolicy() 메서드를 사용하여 세션 생성 정책을 STATELESS로 설정
                // STATELESS를 할 경우 spring Security는 세션을 사용하지 않고 각 요청을 독립적인 작업을 한다.
                // 각 요청이 사용자의 상태를 저장하거나 유지하지 않고 요청마다 인증을 수행하도록 합니다.
                .sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // cors() 메서드는 CORS 구성을 지정합니다. 여기서는 Customizer.withDefaults()를 사용하여 기본 CORS 구성을 활성화합니다.
                // 활성화 한다는 말이 특정 출처나 특정 유형의 요청만 허용하고 모든 출처의 요청을 허용하지 않는다. 그럼 왜 이 코드는 허용이 되는가?
                // application.yml에 (allowed-origins: http://localhost:3000)을 설정하였기 때문에 허용을 하는 것이다.
                .cors(Customizer.withDefaults())

                // CSRF 보호를 비활성화한다.
                // 왜 비활성화 하는 가? JWT 토큰 자체에 사용자의 인증 정보를 포함하고 있기 때문에 각 요청마다 서버에서 세션 상태를 유지할 필요가 없다.
                // 그래서 CSRF 공격을 방지하기 위한 토큰 생성 및 검증이 필요하지 않는다.
                .csrf(AbstractHttpConfigurer::disable)

                // /h2-console/로 시작하는 모든 URL은 CSRF 검증을 하지 않는다는 설정을 추가 스프링 시큐리티가 내부적으로 h2데이터베이스를 막고 있음
                .csrf(csrf -> csrf .ignoringRequestMatchers(new AntPathRequestMatcher("/h2-console/**")))
                // H2 콘솔의 화면이 프레임(frame) 구조로 작성되었기 때문 이 말이 H2 콘솔 UI(user interface) 레이아웃이 이 화면처럼 작업 영역이 나눠져 있다라는 말이다.
                // 스프링 시큐리티는 웹 사이트의 콘텐츠가 다른 사이트에 포함되지 않도록 하기 위해
                // X-Frame-Options 헤더의 기본값을 DENY로 사용하는데, 프레임 구조의 웹 사이트는 이 헤더의 값이 DENY인 경우 이와 같이 오류가 발생한다.
                // URL 요청 시 X-Frame-Options 헤더를 DENY 대신 SAMEORIGIN으로 설정하여 오류가 발생하지 않도록 했다.
                // X-Frame-Options 헤더의 값으로 SAMEORIGIN을 설정하면 프레임에 포함된 웹 페이지가 동일한 사이트에서 제공할 때에만 사용을 허용한다.
                .headers(header -> header
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::disable))

                .build();
    }

    // BCrypt는 안전한 해싱 알고리즘 중 하나로, 해싱된 비밀번호는 매번 생성할 때마다 다른 결과를 가지며, 공격자가 해시값을 역으로 추론하기 어렵다.
    // 해당 메소드는 비밀번호 암호화
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
