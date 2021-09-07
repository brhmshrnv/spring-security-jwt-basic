package az.ibrahimshirinov.SpringSecurityJwt.service.impl;

import az.ibrahimshirinov.SpringSecurityJwt.domain.Role;
import az.ibrahimshirinov.SpringSecurityJwt.domain.User;
import az.ibrahimshirinov.SpringSecurityJwt.repository.RoleRepository;
import az.ibrahimshirinov.SpringSecurityJwt.repository.UserRepository;
import az.ibrahimshirinov.SpringSecurityJwt.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author IbrahimShirinov
 * @since 06.09.2021
 */

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService , UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * @implNote Why UserDetailsService implemented? Because when User try to log in which is registered and saved database before.User should fetch from database using security features(Getting user with roles and convert roles to spring based autorities)
     * @param username
     * @return new SpringSecurityUser
     * @throws UsernameNotFoundException
     */

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if(user == null) {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User found in the database: {}", username);
            Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
            user.getRoles().forEach(role -> {
                authorities.add(new SimpleGrantedAuthority(role.getName()));
            });
            return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
        }
    }

    @Override
    public User saveUser(User user) {
        log.info("Saving new user to database");
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        log.info("Saving new role to database");
        return roleRepository.save(role);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("Adding role: {} to user: {}", roleName,username);
        User user = userRepository.findByUsername(username);
        Role role = roleRepository.findByName(roleName);
        /**
         * Automaticly saving without calling repository. Because @Transactional annotation used.
         */
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        log.info("Fetching user: {}",username);
        return userRepository.findByUsername(username);
    }

    @Override
    public List<User> getUsers() {
        log.info("Feting all users");
        return userRepository.findAll();
    }
}
