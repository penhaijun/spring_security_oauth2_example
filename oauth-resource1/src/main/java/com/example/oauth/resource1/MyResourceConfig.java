package com.example.oauth.resource1;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.RemoteTokenServices;

/**
 * @author penghaijun
 * @description 资源服务器
 * @date 2019-06-11 13:23
 **/
@Configuration
@EnableResourceServer
public class MyResourceConfig extends ResourceServerConfigurerAdapter {

    @Value("${security.oauth.authorization.sever.addr:localhost}")
    private String oauthSeverAddr;
    @Value("${security.oauth.authorization.sever.port:8080}")
    private int oauthSeverPort;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.resourceId("test").stateless(true);
        resources.tokenServices(getRemoteTokenService());
    }

    private RemoteTokenServices getRemoteTokenService() {
        RemoteTokenServices remoteTokenServices = new RemoteTokenServices();
        remoteTokenServices.setClientId("client_1");
        remoteTokenServices.setClientSecret("1234");
        remoteTokenServices.setCheckTokenEndpointUrl(String.format("http://%s:%s/oauth/check_token", oauthSeverAddr, oauthSeverPort));

        return remoteTokenServices;
    }
}
