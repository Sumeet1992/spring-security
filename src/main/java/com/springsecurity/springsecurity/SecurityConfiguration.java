package com.springsecurity.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

// WebSecurityConfigurerAdapter : this class has the configure method

//Below Annotation tells spring security that this is a web security configuration.
// web security is just one of the ways in which we can configure security, the other ways are application/method level security
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // Set your configuration on the auth object

//      In below code, we created inMemoryAuthentication configuration with user, password and role.
        auth.inMemoryAuthentication()
                .withUser("sumeet")
                .password("sumeet")
                .roles("USER")
                .and()
                .withUser("sum")
                .password("sum")
                .roles("ADMIN");

    }
//  Spring Security says that it is not going to assume that the passwords are clear text.
//    it is going to encode passwords and is going to enforce developers to do password encoding
    @Bean
    public PasswordEncoder getPasswordEncoder(){
//      nooppasswordencoder returns nothing.
        return NoOpPasswordEncoder.getInstance();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

//        Below logic tells spring security that all urls should have role of a USER
        //        http.authorizeRequests()
//                .antMatchers("/**").hasRole("USER")

//       formLogin() - the type of login user wants
//        antMatcher is used to specify the path
//        using hasAnyRole, we can pass more than one roles

//                / url is permitted for everyone since it is root url
//        http.authorizeRequests()
//                        .antMatchers("/").permitAll()
//                        .antMatchers("/**").hasAnyRole("ADMIN")
//                        .and().formLogin();

//        we should put most restrictive at the top and so on in decreasing order
        http.authorizeRequests()
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/user").hasAnyRole("USER","ADMIN")
                .antMatchers("/").permitAll()
                .and().formLogin();
    }
}
