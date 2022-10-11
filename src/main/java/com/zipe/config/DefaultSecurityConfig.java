package com.zipe.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author lengleng
 * @date 2021/8/18
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

	// @formatter:off
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorizeRequests -> authorizeRequests
                        .antMatchers("/password/*").permitAll()
                        .antMatchers("/h2-console/*").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        // this will ignore only h2-console csrf, spring security 4+
        http.csrf().ignoringAntMatchers("/h2-console/**");
        //this will allow frames with same origin which is much more safe
        http.headers().frameOptions().sameOrigin();
        return http.build();
    }


    // @formatter:off
    @Bean
    UserDetailsService users() {
        UserDetails user = User.builder()
                .username("user")
                .password("{noop}password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

}
