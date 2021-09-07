package az.ibrahimshirinov.SpringSecurityJwt.repository;

import az.ibrahimshirinov.SpringSecurityJwt.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author IbrahimShirinov
 * @since 06.09.2021
 */
public interface UserRepository extends JpaRepository<User,Long> {

    User findByUsername(String username);
}
