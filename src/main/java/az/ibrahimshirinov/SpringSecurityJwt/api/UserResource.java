package az.ibrahimshirinov.SpringSecurityJwt.api;

import az.ibrahimshirinov.SpringSecurityJwt.domain.Role;
import az.ibrahimshirinov.SpringSecurityJwt.domain.User;
import az.ibrahimshirinov.SpringSecurityJwt.service.UserService;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.*;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

/**
 * @author IbrahimShirinov
 * @since 06.09.2021
 */

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserResource {

    private final UserService userService;


    @GetMapping("/users")
    private ResponseEntity<List<User>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @GetMapping("/{username}")
    private ResponseEntity<User> getUser(@PathVariable String username){
        return ResponseEntity.ok().body(userService.getUser(username));
    }

    @PostMapping("/user/save")
    private ResponseEntity<User> saveUser(@RequestBody User user){
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    private ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<Void> addRoleToUser(@RequestBody RoleToUserForm form){
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }

    @GetMapping("/role/addtouser")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response){
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        if (authorizationHeader !=null && authorizationHeader.startsWith("Bearer ")){
            try {
                String token = authorizationHeader.substring("Bearer ".length());
                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
                JWTVerifier verifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = verifier.verify(token);

                String username = decodedJWT.getSubject();
                String[] roles= decodedJWT.getClaim("roles").asArray(String.class);
                Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                Arrays.stream(roles).forEach(role -> {
                    authorities.add(new SimpleGrantedAuthority(role));
                });
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username,null,authorities);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);

            }catch (Exception e) {
                log.error("Error logging in: {}",e.getMessage());
                response.setHeader("error",e.getMessage());
                response.setStatus(FORBIDDEN.value());
                // response.sendError(FORBIDDEN.value());
                Map<String,String> error= new HashMap<>();
                error.put("error_message",e.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(),error);
            }
        }else {
            throw new RuntimeException("Refresh token is missing");
        }
    }


    @Data
    class RoleToUserForm{
        private String  username;
        private String roleName;
    }


}
