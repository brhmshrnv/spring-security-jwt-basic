package az.ibrahimshirinov.SpringSecurityJwt.repository;

import az.ibrahimshirinov.SpringSecurityJwt.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author IbrahimShirinov
 * @since 06.09.2021
 */
public interface RoleRepository extends JpaRepository<Role,Long> {
    Role findByName(String name);
}
