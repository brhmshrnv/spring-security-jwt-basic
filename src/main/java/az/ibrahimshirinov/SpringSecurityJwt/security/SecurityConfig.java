package az.ibrahimshirinov.SpringSecurityJwt.security;

import az.ibrahimshirinov.SpringSecurityJwt.filter.CustomAuthenticationFilter;
import az.ibrahimshirinov.SpringSecurityJwt.filter.CustomAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

/**
 * @author IbrahimShirinov
 * @since 06.09.2021
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;


    /**
     * {@link SecurityBuilder} used to create an {@link AuthenticationManager}. Allows for
     * easily building in memory authentication, LDAP authentication, JDBC based
     * authentication, adding {@link UserDetailsService}, and adding
     * {@link AuthenticationProvider}'s.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {

        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManagerBean());
        customAuthenticationFilter.setFilterProcessesUrl("/api/login");

        //Cross-Site Request Forgery
        http.csrf().disable();
        // session management is stateless we can't use session or cookies in server side because we use JWT
        http.sessionManagement().sessionCreationPolicy(STATELESS);
        // we are going to allow everyone to be able to access this application at this point
        http.authorizeRequests().antMatchers("/api/login/**").permitAll();
        //we are going to allow to user that's role as ROLE_USER to this endpoint with GET method(** means can access than base path)
        http.authorizeRequests().antMatchers(GET,"/api/user/**").hasAnyAuthority("ROLE_USER");
        //we are going to allow to user that's role as ROLE_ADMIN to this endpoint with POST method
        http.authorizeRequests().antMatchers(POST,"/api/user/save/**").hasAnyAuthority("ROLE_ADMIN");
        // Specify that URLs are allowed by any authenticated user.
        http.authorizeRequests().anyRequest().authenticated();
        // we are going to use authentication filter so that we can check the user whenever they're trying to log in,
        // and we need to tell this configuration about this filter
        http.addFilter(customAuthenticationFilter);
        // this filter will run after authentication. Every request must be pass from this authorization filter
        http.addFilterBefore(new CustomAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);

    }


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception{
        return super.authenticationManagerBean();
    }
}

