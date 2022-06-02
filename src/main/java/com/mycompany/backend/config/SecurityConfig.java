package com.mycompany.backend.config;

import javax.annotation.Resource;

import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.mycompany.backend.security.JwtAuthenticationFilter;

import lombok.extern.log4j.Log4j2;

@Log4j2
@EnableWebSecurity //얘는 이미 @Configuration이 붙어있기 때문에 @Bean을 사용할 수 있음
public class SecurityConfig extends WebSecurityConfigurerAdapter{
  @Resource
  private RedisTemplate redisTemplate;
  
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    log.info("실행");
    //서버 세션을 비활성화(안쓴다!) 기본적으로 세션이 활성화되기 때문에 이를 막아버림! 아예 HttpSession이 생기지 않도록 함
    //아래 코드를 추가하면 J세션 아이디가 생성되지 않음
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    
    //폼 로그인 비활성화
    http.formLogin().disable();
    
    //사이트간 요청 위조 방지 비활성화
    http.csrf().disable();
    
    //요청 경로 권한 설정
    http.authorizeRequests()
      .antMatchers("/board/**").authenticated()
      .antMatchers("/**").permitAll();
    
    //CORS 설정 - 다른 도메인에서 자바스크립트로 접근할 수 있도록 설정하는 것!(필수!!!***)
    //다른 도메인의 자바스크립트로 접근을 할 수 있도록 허용하는것을 의미
    http.cors();
    
    //JWT 인증 필터 추가(필터는 아무때나 추가하면 안되고, 인증 필터는 지정된 곳에서만..!)
    //폼인증 필드가 동작하기 전에 해야! 따라서 addFilterBefore로 
    //폼로그인을 비활성화하기 때문에, 우리가 만든 jwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter전에 추가해줘! 라는 것!
    //jwtAuthenticationFilter을 관리 객체로 만들었기 때문에, new JwtAuthenticationFilter()로 하지 않는다!(새로 만들면 관리 객체가 아님!)
    http.addFilterBefore(jwtAuthenticationFilter() , UsernamePasswordAuthenticationFilter.class);
    
  }
  
  //setter로 ReidsTemplate를 주입!
  //다른곳에서 사용을 하면 관리객체로 만들어야 하지만, 그렇지 않기 때문에, 굳이 @Bean을 붙여서 관리객체로 만들 필요는 없을 것 같음
  public JwtAuthenticationFilter jwtAuthenticationFilter() {
    JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter();
    jwtAuthenticationFilter.setRedisTemplate(redisTemplate);
    return jwtAuthenticationFilter;
  }
  
  //DB에서 무엇을 가져올 것인가! 에 ..대한 것임
  //패스워드 인코더를 뭘 쓸건가
  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    log.info("실행");
    
    //폼인증 방식에서 사용!
    /*
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    //DB에서 멤버에 대한 정보를 가져옴!
    provider.setUserDetailsService(new CustomUserDetailsService());
    //비밀번호를 비교하기 위해 
    provider.setPasswordEncoder(passwordEncoder());
    auth.authenticationProvider(provider);
    */
  }
  
  @Override
  public void configure(WebSecurity web) throws Exception {
    log.info("실행");
    
    //여기선 얘만 사용해도 된다!
    DefaultWebSecurityExpressionHandler defaultWebSecurityExpressionHandler = new DefaultWebSecurityExpressionHandler();
    defaultWebSecurityExpressionHandler.setRoleHierarchy(roleHierarchyImpl());   
    web.expressionHandler(defaultWebSecurityExpressionHandler);
   
    //MPA방식에서 시큐리티를 적용하지 않는 경로를 설정하는 것임!! 즉 사용할 필요 없음
    /*
    web.ignoring()
      .antMatchers("/images/**")
      .antMatchers("/css/**")
      .antMatchers("/js/**")
      .antMatchers("/bootstrap/**")
      .antMatchers("/jquery/**")
      .antMatchers("/favicon.ico");
      */
  }

  //회원가입할 때와 인증할 때의 암호화방식은 같아야 함
  @Bean
  public PasswordEncoder passwordEncoder() {
//    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    return new BCryptPasswordEncoder();
  }
  
  @Bean
  public RoleHierarchyImpl roleHierarchyImpl() {
     log.info("실행");
     RoleHierarchyImpl roleHierarchyImpl = new RoleHierarchyImpl();
     roleHierarchyImpl.setHierarchy("ROLE_ADMIN > ROLE_MANAGER > ROLE_USER");
     return roleHierarchyImpl;
  }
  
  //REST API에서만 사용해!!!!!!!!!!!!!!!!!!!!!!!
  //cors를 활성화하면 이 내부에서 CorsConfigurationSource얘가 있는지 확인을 함!
  //있으면 안의 정보를 확인하고  자바스크립트에서 허용을 해줄건지 말건지 함... 즉 여기서 설정하면 됨!
  //CorsConfigurationSource와 이름이 같은게 좋음!(CorsConfigurationSource에서 앞에만 소문자로 해서 만드는게 좋음!)
  @Bean
  public CorsConfigurationSource corsConfigurationSource() {
      log.info("실행");
      CorsConfiguration configuration = new CorsConfiguration();
      //모든 요청 사이트 허용
      configuration.addAllowedOrigin("*");
      //모든 요청 방식 허용
      configuration.addAllowedMethod("*");
      //모든 요청 헤더 허용
      configuration.addAllowedHeader("*");
      //모든 URL 요청에 대해서 위 내용을 적용
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      //모든 요청에 대해...
      source.registerCorsConfiguration("/**", configuration);
      return source;
  }
}
