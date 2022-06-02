package com.mycompany.backend.security;

import java.io.IOException;
import java.util.Map;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import lombok.extern.log4j.Log4j2;

//해당 filter가 실행되면 검증을 진행하는 것임!
//얘는 관리 객체가 아니기때문에 @Resource를 사용할 수 없음!
@Log4j2
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private RedisTemplate redisTemplate;
  public void setRedisTemplate(RedisTemplate redisTemplate) {
    this.redisTemplate = redisTemplate;
  }


  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    log.info("실행");
    
    //로그인 인증을 여기서 해줘어~
    String authorization = request.getHeader("Authorization");
    
    //AccessToken 추출
    String accessToken = Jwt.getAccessToken(authorization);
    
    //검증 작업
    //redisRefreshToken 자체를 검증하는 것은 아님!
    //redisRefreshToken얘가 없다는 것은 accessToken이 없다는 얘기임!
    if(accessToken != null && Jwt.validateToken(accessToken)) {
      
      //Redis에 존재 여부 확인(로그아웃할 때 Redis에서도 삭제되므로..!)
      ValueOperations<String, String> vo = redisTemplate.opsForValue();
      String redisRefreshToken = vo.get(accessToken);
      
      if(redisRefreshToken != null) {
        //인증 처리
        Map<String, String> userInfo = Jwt.getUserInfo(accessToken);
        String mid = userInfo.get("mid");
        String authority = userInfo.get("authority");
        
        //authentication 객체가 있으면 인증이 된 것이고 없으면 인증처리가 되지 않은 것이다!
        UsernamePasswordAuthenticationToken authentication = 
            new UsernamePasswordAuthenticationToken(mid, null,AuthorityUtils.createAuthorityList(authority));
        SecurityContext securityContext = SecurityContextHolder.getContext();
        securityContext.setAuthentication(authentication);
      }
    }
    //다음 doFilter를 실행할 때는 일단 인증은 되었다고 생각하면 됨! 즉 클라이언트가 이미 access Token을 받은 상태
    filterChain.doFilter(request, response);
  }
}
