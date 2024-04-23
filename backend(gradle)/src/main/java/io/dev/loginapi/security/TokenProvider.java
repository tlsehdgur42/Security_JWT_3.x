package io.dev.loginapi.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider {

    // @Value 애노테이션을 사용하여 Spring의 application.properties, yml 에서 값을 가져온다.
    // jwtSecret 는 JWT를 생성 및 검증할 때 사용할 시크릿 키(비밀 키), 보안상 민감한 정보이기 때문에 외부에 노출x !!!
    @Value("${app.jwt.secret}")
    private String jwtSecret;

    // yml파일에 minutes가 (유효시간, 만료시간)10분으로 설정해 10분 후에 만료되도록 설정했다.
    @Value("${app.jwt.expiration.minutes}")
    private Long jwtExpirationMinutes;


    // 사용자의 인증 정보를 기반으로 JWT 를 생성하는 메서드
    public String generate(Authentication authentication) {
        // (Authentication)사용자의 인증 정보에서 사용자의 세부 정보를 추출
        CustomUserDetails user = (CustomUserDetails) authentication.getPrincipal();

        // 사용자의 권한을 가져와서 스트림을 이용하여 문자열 리스트로 변환
        List<String> roles = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        // JWT 서명에 사용할 키를 생성합니다. JWT 서명(Signature)은 JWT를 생성할 때 사용되는 고유한 키, 서명은 JWT의 무결성을 보장하고, 토큰이 변경되지 않았음을 검증하는 데 사용된다.
        // JWT를 생성할 때 서명 키는 바이트 배열(byte array) 형태이다. 이 바이트 배열은 일반적으로 시크릿 키(Secret Key)나 공개 키(Public Key)의 형태로 제공한다.
        byte[] signingKey = jwtSecret.getBytes();

        // JWT 빌더를 사용해서 토큰 생성
        return Jwts.builder()
                // JWT의 헤더(HTTP header)는 두가지의 정보를 포함하는데 토큰의 유형(typ)과 사용된 서명 알고리즘(alg)이다.
                // 헤더에 typ 필드를 추가하면 JWT가 어떤 유형의 토큰인지 명시되며, 클라이언트 및 서버에서 토큰을 처리할 때 이를 구분할 수 있다.
                .header().add("typ", TOKEN_TYPE)
                .and()
                // 서명에 사용될 알고리즘과 키를 설정한다.
                // HMAC-SHA512 알고리즘을 사용하고, 위에 생성한 서명 키(signingKey)를 사용한다.
                .signWith(Keys.hmacShaKeyFor(signingKey), Jwts.SIG.HS512)

                //== 토큰의 만료 시간, 발급 시간, 고유 식별자, 발급자, 대상 청중을 설정 ==//
                // JWT의 만료 시간을 설정하는 부분이다. Date.from() 메서드를 사용하여 이 새로운 시간을 java.util.Date 객체로 변환한다..
                // JWT의 만료 시간은 expiration() 메서드를 사용하여 설정되며, 이를 통해 JWT가 특정 시간 이후에 더 이상 유효하지 않게 한다.
                .expiration(Date.from(ZonedDateTime.now().plusMinutes(jwtExpirationMinutes).toInstant()))
                // JWT의 발급 시간을 설정하는 부분이다.
                // issuedAt() 메서드를 사용하여 JWT의 발급 시간을 설정한다.
                .issuedAt(Date.from(ZonedDateTime.now().toInstant()))
                // JWT의 고유 식별자(ID)클레임을 설정하는 부분이다. JWT의 페이로드에 고유 식별자(ID) 클레임을 추가하여 JWT의 식별성을 보장한다.
                // 페이로드 란 토큰에 포함되는 정보를 담고 있는 부분(사용자에 대한 정보, 권한, 토큰자체에 관련된 기타 정보)
                // UUID는 128비트의 수이며, 보통 32개의 16진수 문자로 표현되며 randomUUID()메서드로 랜덤(무작위)로 UUID를 생성하고 문자열로 변환한다. UUID를 사용하는 이유는 토큰의 중복사용, 위조 방지를 하여 고유한 값을 만들 수 있어서
                .id(UUID.randomUUID().toString())
                // JWT의 발급자(issuer) 클레임을 설정하는 부분이다.
                // LogInTimeStamp 애플리케이션의 API에서 발급된 토큰임을 나타낼 수 있다.
                // 이렇게 발급자 클레임을 설정하면 토큰을 검증하는 곳에서 발급자를 신뢰할 수 있는 출처로 인식할 수 있다.
                .issuer(TOKEN_ISSUER)
                // JWT의 대상 청중(audience) 클레임을 설정하는 부분이다. 대상 청중 클레임은 토큰이 제한되는 대상을 말한다.
                // 즉, 특정한 수신자나 그룹에게 토큰을 제한하여 사용할 수 있도록 한다.
                .audience().add(TOKEN_AUDIENCE)
                .and()
                // JWT의 주제(subject) 클레임을 설정하는 부분이다. JWT의 주제 클레임은 토큰에 대한 주제를 말한다. 토큰에 포함된 정보의 주요 주제를 식별하며, 주로 토큰을 받는 측이 이를 사용하여 특정 사용자나 리소스를 식별한다.
                // CustomUserDetails 객체에서 사용자의 이름을 가져온다. 이 이름을 주제 클레임으로 설정하여 토큰이 어떤 사용자를 나타내는 지 말한다.
                .subject(user.getUsername())

                //== JWT의 클레임(claim)을 설정하는 부분이다 ==//
                // roles 리스트에는 사용자의 역할(권한) 정보를 포함하고 있으며
                // JWT 클레임에 추가함으로써 토큰을 검증하는 시스템에서 해당 사용자가 어떤 권한을 가지고 있는 지를 확인한다.
                .claim("rol", roles)
                // JWT에 사용자의 이름 정보가 포함되며, 이를 통해 토큰을 검증하는 시스템에서는 해당 사용자의 이름을 확인할 수 있다.
                .claim("name", user.getName())
                // JWT에 사용자의 아이디 정보가 포함되며, 이를 통해 토큰을 검증하는 시스템에서는 해당 사용자의 아이디를 확인할 수 있다.
                .claim("preferred_username", user.getUsername())
                // JWT에 사용자의 이메일 정보가 포함되며, 이를 통해 토큰을 검증하는 시스템에서는 해당 사용자의 이메일을 확인할 수 있다.
                .claim("email", user.getEmail())
                // .compact()은 JWT를 문자열 형태로 직렬화하는 메서드
                .compact();
    }

    // Jws<Claims> JWT 서명을 포함한 클레임을 말한다.
    // 유효한 토큰에 대해 해당 토큰의 클레임을 포함한 Jws<Claims> 객체를 반환하거나, 토큰이 유효하지 않은 경우 비어있는 Optional 객체를 반환한다.
    public Optional<Jws<Claims>> validateTokenAndGetJws(String token) {
        try {
            // JWT 서명에 사용할 키를 생성합니다.
            byte[] signingKey = jwtSecret.getBytes();

            // .parser()메서드를 호출하면 JWT를 파싱하기 위한 새로운 파서 인스턴스가 생성된다.
            // 파싱이란 주어진 데이터를 구문 분석하여 의미있는 구조로 변환하는 과정, 특정 데이터 형식을 인식하고 추출하기 위해 데이터를 분석하고 해석, JSON 문자열을 파싱하여 JavaScript 객체로 변환하는 것은 JSON 파싱
            Jws<Claims> jws = Jwts.parser()
                    // .verifyWith(Keys.hmacShaKeyFor(signingKey)) 생성된 JWT 파서에 서명 검증을 수행하는데 사용할 키를 지정하는 것
                    // Keys.hmacShaKeyFor(signingKey)는 바이트 배열 형태의 서명 키를 이용하여 HMAC-SHA 알고리즘을 사용하여 서명을 검증하는 데 필요한 키를 생성
                    .verifyWith(Keys.hmacShaKeyFor(signingKey))
                    .build()
                    // JWT 파서가 서명을 검증하고 토큰의 내용을 검증한 후, 토큰에 포함된 클레임을 가져온다.
                    // 이 클레임은 토큰에 포함된 정보를 나타내며, 예를 들어 사용자 ID, 권한 등의 정보를 포함할 수 있다.
                    .parseSignedClaims(token);

            return Optional.of(jws);
        } catch (ExpiredJwtException exception) {
            log.error("만료된 JWT를 해석하는 요청이 실패했습니다: ", token, exception.getMessage());
        } catch (UnsupportedJwtException exception) {
            log.error("지원되지 않는 JWT 형식을 해석하는 요청이 실패했습니다: ", token, exception.getMessage());
        } catch (MalformedJwtException exception) {
            log.error("잘못된 형식의 JWT를 해석하는 요청이 실패했습니다: ", token, exception.getMessage());
        } catch (SignatureException exception) {
            log.error("잘못된 서명이 포함된 JWT를 해석하는 요청이 실패했습니다: ", token, exception.getMessage());
        } catch (IllegalArgumentException exception) {
            log.error("값이 비어있거나 null인 JWT를 해석하는 요청이 실패했습니다: ", token, exception.getMessage());
        }
        return Optional.empty();
    }

    public static final String TOKEN_TYPE = "JWT";
    // "LogInTimeStamp-api"라는 애플리케이션이 토큰을 발급했음을 의미합니다.
    public static final String TOKEN_ISSUER = "LogInTimeStamp-api";
    // "LogInTimeStamp-app"이라는 애플리케이션이 토큰의 대상이 됩니다.
    public static final String TOKEN_AUDIENCE = "LogInTimeStamp-app";
}
