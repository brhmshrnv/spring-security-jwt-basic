package az.ibrahimshirinov.SpringSecurityJwt.service;

import az.ibrahimshirinov.SpringSecurityJwt.domain.Role;
import az.ibrahimshirinov.SpringSecurityJwt.domain.User;

import java.util.List;

/**
 * @author IbrahimShirinov
 * @since 06.09.2021
 */
public interface UserService {

     User saveUser(User user);
     Role saveRole(Role role);
     void addRoleToUser(String username, String roleName);
     User getUser(String username);
     List<User> getUsers();
}
