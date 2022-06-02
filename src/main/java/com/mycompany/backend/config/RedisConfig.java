package com.mycompany.backend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import lombok.extern.log4j.Log4j2;

@Log4j2
@Configuration
public class RedisConfig {
  @Value("${spring.redis.hostName}")
  private String hostName;
  
  @Value("${spring.redis.port}")
  private int port;
  
  @Value("${spring.redis.password}")
  private String password;
  
  //redis 연결 정보를 config에 넣어줌!
  @Bean
  public RedisConnectionFactory redisConnectionFactory() {
    log.info("실행");
    RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
    config.setHostName(hostName);
    config.setPort(port); //redis 포트!
    config.setPassword(password);
    LettuceConnectionFactory connectionFactory = new LettuceConnectionFactory(config);
    return connectionFactory;
  }
  
  //의존주입한 객체를 관리객체로 만들어줌!
  //<저장할 키 , 값>
  @Bean
  public RedisTemplate<String, String> redisTemplate(){
    log.info("실행");
    RedisTemplate<String, String> redisTemplate = new RedisTemplate<>();
    redisTemplate.setConnectionFactory(redisConnectionFactory());
    redisTemplate.setKeySerializer(new StringRedisSerializer()); //키, 벨류를 작성 가능한 형태 즉 바이트배열로 작성해라
    redisTemplate.setValueSerializer(new StringRedisSerializer());//바이트배열로 만들 객체를 괄호안에 넣어라!
    return redisTemplate;
  }
}