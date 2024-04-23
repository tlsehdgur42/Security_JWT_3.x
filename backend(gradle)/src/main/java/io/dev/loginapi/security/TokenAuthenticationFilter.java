package io.dev.loginapi.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Component
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    // 사용자 세부 정보
    private final UserDetailsService userDetailsService;
    // JWT 토큰 객체
    private final TokenProvider tokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws ServletException, IOException {
        try {
            // 사용자의 요청신호가 들어오면 HTTP 요청에서 JWT를 가져온다.
            getJwtFromRequest(request)

                    // flatMap은 Optional 메서드로 Optional 객체가 비어있지 않을 경우만 실행된다.
                    // 가져온 JWT를 유효성 검사하고 JWS를 가져온다. 만약 유효한 토큰이 없으면 빈 Optional 객체를 반환한다.
                    .flatMap(tokenProvider::validateTokenAndGetJws)

                    // Optional 객체가 값이 존재할 경우 ifPresent() 메서드가 실행된다. 이 코드는 JWT가 유효하고 JWS가 존재하면 실행된다.
                    .ifPresent(jws -> {
                        // 가져온 JWT의 본문(HTTP header)에서 사용자의 이름을 가져온다
                        String username = jws.getBody().getSubject();
                        // 요청이 들어온 사용자의 식별정보 및 권한 등 세부정보를 가져온다.
                        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                        // userDetails 요청이 들어온 사용자의 세부 정보와 userDetails.getAuthorities() 권한을 가지고 인증을 토큰 객체로 만든다.
                        // JWT 인증 방식에서는 패스워드를 사용하지 않기 때문에 credentials(두번째 매개변수)에 null로 세팅했다.
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        // 토큰 객체에 HTTP 요청에 대한 세부 정보(클라이언트의 IP 주소, 요청을 보낸 시간, 사용된 브라우저나 기기에 대한 정보, 요청의 URL 등등)를 가지고 WebAuthenticationDetails 객체 생성한다.
                        // WebAuthenticationDetails 는 Spring Security에서 사용되는 인증에 대한 추가적인 세부 정보를 나타내는 클래스입니다.
                        // 주로 클라이언트의 IP 주소, 세션 ID 등의 정보를 포함하며, 인증 이벤트를 더 자세하게 기록하고 추적하는 데 사용됩니다
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        // SecurityContextHolder 는 현재 실행 중인 스레드에 대한 보안 컨텍스트를 제공하는 역할하는데 보안 컨텍스트란 현재 실행중인 스레드에 대한 보안 정보를 저장하고 관리하는 방?
                        // getContext()메서드는 현재 실행 중인 보안 컨텍스트를 반환하고
                        // setAuthentication(authentication) 메서드는 해당 보안 컨텍스트에 사용자의 인증 정보를 설정합니다.
                        // 이 코드는 Spring Security 가 현재 사용자가 누구인지에 대한 정보를 유지하고, 인증된 사용자에 대한 권한 및 접근 제어를 처리할 수 있습니다.
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    });
        } catch (Exception e) {
            log.error("Cannot set user authentication", e);
        }
        chain.doFilter(request, response);
    }

    private Optional<String> getJwtFromRequest(HttpServletRequest request) {
        String tokenHeader = request.getHeader(TOKEN_HEADER);
        if (StringUtils.hasText(tokenHeader) && tokenHeader.startsWith(TOKEN_PREFIX)) {
            return Optional.of(tokenHeader.replace(TOKEN_PREFIX, ""));
        }
        return Optional.empty();
    }

    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
}
