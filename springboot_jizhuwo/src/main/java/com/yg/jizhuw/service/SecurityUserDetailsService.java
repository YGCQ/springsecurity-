package com.yg.jizhuw.service;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class SecurityUserDetailsService implements UserDetailsService {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        // 数据库存储密码为加密后的密文（明文为123456）
         String password = passwordEncoder.encode("123456");
        System.out.println("username"+s);
        System.out.println("password"+password);
        // 模拟查询数据库，获取属于Admin和Normal角色的用户
        User user=new User(s,password, AuthorityUtils.commaSeparatedStringToAuthorityList("Admin,Normal"))  ;
        return user;
    }
}
