package com.example.oauthserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @author penghaijun
 * @description MyWebSecurityConfig
 * @date 2019-06-11 14:49
 **/
@Configuration
public class MyWebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public AuthenticationManager getAuthenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(myDaoAuthenticationProvider());
        auth.inMemoryAuthentication()
                .passwordEncoder(NoOpPasswordEncoder.getInstance())
                .withUser("admin").password("123").roles("ADMIN")
                .and()
                .withUser("user").password("123").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        super.configure(http);
        http.authorizeRequests()
//                .antMatchers("/oauth/**").permitAll()
                .anyRequest().authenticated()
                .and().formLogin().permitAll();
    }

    public DaoAuthenticationProvider myDaoAuthenticationProvider() {
        DaoAuthenticationProvider myAuthenProvider = new DaoAuthenticationProvider();
        myAuthenProvider.setHideUserNotFoundExceptions(false);
        myAuthenProvider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());

        InMemoryUserDetailsManager inMemoryUserDetailsManager = new InMemoryUserDetailsManager();
        inMemoryUserDetailsManager.createUser(User.withUsername("admin").password("123").roles("ADMIN").passwordEncoder(NoOpPasswordEncoder.getInstance()::encode).build());
        inMemoryUserDetailsManager.createUser(User.withUsername("user").password("123").roles("USER").passwordEncoder(NoOpPasswordEncoder.getInstance()::encode).build());
        myAuthenProvider.setUserDetailsService(inMemoryUserDetailsManager);
        return myAuthenProvider;
    }
}
