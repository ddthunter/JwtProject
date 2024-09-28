package com.example.backend.config;

import com.example.backend.entity.ResultBean;
import com.example.backend.entity.vo.response.AuthorizeVO;
import com.example.backend.filter.JwtAuthorizeFilter;
import com.example.backend.utils.JwtUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Configuration
public class SecurityConfiguration {

    @Resource
    JwtUtils jwtUtils;
    @Resource
    JwtAuthorizeFilter jwtAuthorizeFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(conf -> conf
                        .loginProcessingUrl("/api/auth/login")
                        .successHandler(this::onAuthenticationSuccess)
                        .failureHandler(this::onAuthenticationFailure)
                )
                .logout(conf -> conf
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(this::onLogoutSuccess))
                .exceptionHandling(conf -> conf
                        .authenticationEntryPoint(this::onUnauthorized)
                        .accessDeniedHandler(this::onAccessDeny))
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .addFilterBefore(jwtAuthorizeFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

    /**
     *  有登录token但没有权限
     */
    private void onAccessDeny(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(ResultBean.forbidden(e.getMessage()).asJsonString());
    }

    /**
     * 无登录token
     */
    public void onUnauthorized(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(ResultBean.unauthorized(authException.getMessage()).asJsonString());
    }

    /**
     * /api/auth/login 登录成功
     */
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        User user = (User) authentication.getPrincipal();
        String token = jwtUtils.createJwt(user, 1L, "小明");
        response.getWriter().write(ResultBean.success(AuthorizeVO.builder().username("小明").token(token).role("").expire(jwtUtils.expiresTime()).build()).asJsonString());
    }

    /**
     * /api/auth/login 登录失败
     */
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write(ResultBean.unauthorized(exception.getMessage()).asJsonString());
    }

    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // todo logoutSuccess
    }
}
