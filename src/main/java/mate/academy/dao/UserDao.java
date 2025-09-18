package mate.academy.dao;

import mate.academy.model.User;

import java.util.Optional;

public interface UserDao {
    User save(User user);

    Optional<User> getByEmail(String email);
}
