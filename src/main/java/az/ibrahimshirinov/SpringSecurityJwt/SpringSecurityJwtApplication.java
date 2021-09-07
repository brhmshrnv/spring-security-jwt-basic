package az.ibrahimshirinov.SpringSecurityJwt;

import az.ibrahimshirinov.SpringSecurityJwt.domain.Role;
import az.ibrahimshirinov.SpringSecurityJwt.domain.User;
import az.ibrahimshirinov.SpringSecurityJwt.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder () {
		return new BCryptPasswordEncoder();
	}
}
