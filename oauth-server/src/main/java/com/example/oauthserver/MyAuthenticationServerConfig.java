package com.example.oauthserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;

/**
 * @author penghaijun
 * @description 授权服务器配置
 * @date 2019-06-11 13:09
 **/
@Configuration
@EnableAuthorizationServer
public class MyAuthenticationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private AuthenticationManager manager;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 允许表单认证
        security.allowFormAuthenticationForClients();
        security
                // 开启 /oauth/token_key 验证端口无权限访问
                .tokenKeyAccess("permitAll()")
                // 开启 /oauth/check_token 验证端口认证权限访问
                .checkTokenAccess("isAuthenticated()");
    }


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
//        super.configure(endpoints);
        endpoints.authenticationManager(manager);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.inMemory().withClient("client_1")
                .secret("1234")
                .resourceIds("test")
                .scopes("test")
                .redirectUris("http://localhost:8080")
                .authorizedGrantTypes("client_credentials", "refresh_token")
                .authorities("client")
                // client2
                .and().withClient("client_2")
                .resourceIds("test")
                .scopes("test")
                .redirectUris("http://localhost:8080")
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .secret(passwordEncoder.encode("1234"))
                .authorities("client");
    }


    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder(8);
    }

}
