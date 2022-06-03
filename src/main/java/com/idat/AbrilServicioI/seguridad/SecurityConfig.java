package com.idat.AbrilServicioI.seguridad;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter{

//	@Autowired
//	private PasswordEncoder encriptado;
	@Autowired
	private UserDetailService service;
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//		auth.inMemoryAuthentication().withUser("queridoprofesor").password( encriptado().encode("123456") ).roles("ADMIN");
//		auth.inMemoryAuthentication().withUser("alumno").password( encriptado().encode("123456") ).roles("ALUMNO");
		auth.userDetailsService(service).passwordEncoder(encriptado());
	}

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
			.antMatchers("/producto/v1/*").access("hasRole('USER')")
			.and()
			.httpBasic()
			.and()
			.csrf().disable();
	}

	@Bean
	public PasswordEncoder encriptado() {
		return new BCryptPasswordEncoder();
	}

	
}
