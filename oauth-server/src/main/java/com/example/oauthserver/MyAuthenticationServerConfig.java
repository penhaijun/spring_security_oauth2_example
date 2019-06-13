package com.example.oauthserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

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
    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 允许表单认证
        security.allowFormAuthenticationForClients();
        security
                // 开启 /oauth/token_key 验证端口无权限访问
                // 如果用的是 jwtToken 时，是需要对token进行签名的，这里是获取 public-key 的接口，默认是 denyAll
                .tokenKeyAccess("permitAll()")
                // 开启 /oauth/check_token 验证端口认证权限访问
                // 资源服务器向授权服务器验证token的接口
                .checkTokenAccess("isAuthenticated()");
    }


    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(manager);
        endpoints.userDetailsService(userDetailsService);
        JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
        tokenConverter.setSigningKey("1234");
        endpoints.accessTokenConverter(tokenConverter);
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

        clients.inMemory()
                // implicit 模式
                // http://localhost:8081/oauth/authorize?response_type=token&client_id=client_1&scope=test
                .withClient("client_1")
                // 中间其实用不到密码
                .secret(passwordEncoder.encode("1234"))
                .resourceIds("test")
                .scopes("test")
                .redirectUris("http://localhost:8080")
                .authorizedGrantTypes("implicit")
                .authorities("client")

                // client2 授权码模式 authorization_code
                // 1 取得 authorization_code   : http://localhost:8081/oauth/authorize?response_type=code&client_id=client_2&redirect_uri=http://localhost:8080&scope=test
                // 2:返回code 结果如:http://localhost:8080/?code=60n6zt  // 其中 60n6zt 就是授权码
                // 3：根据CODE取是TOKEN : POST  http://localhost:8081/oauth/token?client_id=client_2&client_secret=1234&grant_type=authorization_code&code=F2GTNX&redirect_uri=http://localhost:8080
                .and().withClient("client_2")
                .resourceIds("test")
                .scopes("test")
                .redirectUris("http://localhost:8080")
                .authorizedGrantTypes("authorization_code", "refresh_token")
                .secret(passwordEncoder.encode("1234"))
                .authorities("client")
                .and()

                // 密码模式
                // http://localhost:8081/oauth/token?grant_type=password&username=admin&password=123&client_id=client_3&client_secret=1234
                .withClient("client_3")
                .resourceIds("test")
                .scopes("test")
                .authorizedGrantTypes("password", "refresh_token")
                .secret(passwordEncoder.encode("1234"))
                .authorities("client")

                // 客户端凭证模式
                // http://localhost:8081/oauth/token?grant_type=client_credentials&client_id=client_4&client_secret=1234
                .and()
                .withClient("client_4")
                .authorizedGrantTypes("client_credentials")
                .resourceIds("test")
                .scopes("test")
                .secret(passwordEncoder.encode("1234"))
                .authorities("client");

        // 刷新 token
        // POST: http://localhost:8081/oauth/token?grant_type=refresh_token&client_id=client_2&client_secret=1234&refresh_token=e0172e46-12de-41b0-ac9e-facb3bd71d50

    }


    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder(8);
    }

}
