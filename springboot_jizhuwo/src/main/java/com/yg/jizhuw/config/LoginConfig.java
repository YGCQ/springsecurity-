package com.yg.jizhuw.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

@Configuration
public class LoginConfig extends WebSecurityConfigurerAdapter {


    @Autowired
    private UserDetailsService userDetailsService;

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Autowired
    private DataSource dataSource;
    
    @Bean
     public PersistentTokenRepository tokenRepository(){
        JdbcTokenRepositoryImpl tokenRepository=new JdbcTokenRepositoryImpl();
        tokenRepository.setDataSource(dataSource);
        return tokenRepository;
    }
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                // 设置不需要授权的请求
                .antMatchers( "/login.html").permitAll()

                // 其它任何请求都需要验证权限
                .anyRequest().authenticated()

                // 设置自定义表单登录页面
                .and().formLogin().loginPage("/login.html")

                // 设置登录验证请求地址为自定义登录页配置action （"/login/form"）
                .loginProcessingUrl("/login/form")

                // 设置默认登录成功跳转页面
                .defaultSuccessUrl("/main.html")

                // 添加记住我功能
                .and().rememberMe().tokenRepository(tokenRepository())

                // 有效期为两周
                .tokenValiditySeconds(3600 * 24 * 14)

                // 设置UserDetailsService
                .userDetailsService(userDetailsService)

                // 暂时停用csrf，否则会影响验证
                .and().csrf().disable();
    }


}
