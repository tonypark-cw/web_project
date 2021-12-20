package com.kingsman.oauth2.security;

import static com.kingsman.oauth2.security.SocialType.GOOGLE;
import static com.kingsman.oauth2.security.SocialType.NAVER;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.session.HttpSessionEventPublisher;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws java.lang.Exception {
		http
			.authorizeRequests()
				.antMatchers("/**", "/oauth2/**", "/login/**", "/css/**", "/images/**", 
						"/js/**", "/console/**","/favicon.ico/**", "/KingsMan/member/**")
					.permitAll()
				.antMatchers("/google").hasAuthority(GOOGLE.getRoleType())
				.anyRequest()
					.authenticated()
			.and()
				.oauth2Login()
				.userInfoEndpoint()
				.userService(new CustomOAuth2UserService()) 
			// Naver User Info의응답을 처리하기 위한 설정
			.and()
				.defaultSuccessUrl("/loginSuccess")
				.failureUrl("/loginFailure")
			.and()
				.exceptionHandling()
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
		http.logout().logoutUrl("/logout").logoutSuccessUrl("/login").invalidateHttpSession(true)
		.deleteCookies("JSESSIONID").permitAll();
//		http.csrf().disable();
	}
	
	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}// Register HttpSessionEventPublisher

	@Bean
	public static ServletListenerRegistrationBean httpSessionEventPublisher() {
		return new ServletListenerRegistrationBean(new HttpSessionEventPublisher());
	}
}