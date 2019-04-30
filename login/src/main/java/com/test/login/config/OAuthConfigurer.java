package com.test.login.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import javax.sql.DataSource;
import java.security.KeyPair;

@Configuration
@EnableAuthorizationServer
public class OAuthConfigurer extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    @Autowired
    @Qualifier("customUserDetailsService")
    private UserDetailsService userDetailsService;

//    @Autowired
//    @Qualifier("dataSource")
//    private DataSource dataSource;

    @Autowired
    private PasswordEncoder passwordEncoder;

//    @Bean
//    public JwtAccessTokenConverter jwtAccessTokenConverter() {
//        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
//        KeyPair keyPair = new KeyStoreKeyFactory(new ClassPathResource(
//                "keystore.jks"), "tc123456".toCharArray()).getKeyPair("tycoonclient");
//        converter.setKeyPair(keyPair);
//        return converter;
//    }

//    @Bean
//    public TokenStore jwtTokenStore() {
//        return new JwtTokenStore(jwtAccessTokenConverter());
//    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
//        clients.inMemory().withClient("ssoclient").secret("ssosecret")
//                .autoApprove(true) //自动确认授权，用户登录后，不再需要进行一次授权确认操作。
//                .authorizedGrantTypes("authorization_code", "refresh_token").scopes("openid");
        clients.inMemory()
                .withClient("client")
                .secret(passwordEncoder.encode("secret"))
                .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
                .scopes("all")
                .accessTokenValiditySeconds(60*60*24)//token有效期为24小时
                .refreshTokenValiditySeconds(600) //刷新token有效期为600秒
                .autoApprove(true)//;//自动确认授权，用户登录后，不再需要进行一次授权确认操作。
                .redirectUris("http://localhost:8081/", "http://localhost:8081/login", "http://localhost:8081/user", "http://localhost:8082", "http://localhost:8082/login", "http://localhost:8082/user", "http://www.example.com/");  //指定可以接受令牌和授权码的重定向URIs
    }

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security)
            throws Exception {
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints)
            throws Exception {
        //endpoints.accessTokenConverter(jwtAccessTokenConverter());
        // 配置 tokenStore，保存到 redis 缓存中
        endpoints.authenticationManager(authenticationManager)
                //.tokenStore(new CustomRedisTokenStore(redisConnectionFactory))
                .tokenStore(new RedisTokenStore(redisConnectionFactory))
                // 不添加 userDetailsService，刷新 access_token 时会报错(无法加载用户信息)
                .userDetailsService(userDetailsService);
    }

}
