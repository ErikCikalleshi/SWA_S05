package at.qe.skeleton.services;

import at.qe.skeleton.model.Userx;

import java.io.*;
import java.util.Collection;
import java.util.Date;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import at.qe.skeleton.repositories.UserxRepository;

/**
 * Service for accessing and manipulating user data.
 * <p>
 * This class is part of the skeleton project provided for students of the
 * course "Software Architecture" offered by Innsbruck University.
 */
@Component
@Scope("application")
public class UserxService {

    @Autowired
    private UserxRepository userRepository;



    private PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    private FileWriter fileWriter;

    public UserxService() throws FileNotFoundException {

        new PrintWriter("auditLog.csv").close();
        try {
            fileWriter = new FileWriter("auditLog.csv", true);
            //write csv
            fileWriter.append("Username");
            fileWriter.append(",");
            fileWriter.append("Delted User");
            fileWriter.append(",");
            fileWriter.append("Date");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    /**
     * Returns a collection of all users.
     *
     * @return
     */
    @PreAuthorize("hasAuthority('ADMIN')")
    public Collection<Userx> getAllUsers() {
        return userRepository.findAllNotDeleted();
    }

    /**
     * Loads a single user identified by its username.
     *
     * @param username the username to search for
     * @return the user with the given username
     */
    @PreAuthorize("hasAuthority('ADMIN') or principal.username eq #username")
    public Userx loadUser(String username) {
        return userRepository.findFirstByUsername(username);
    }

    /**
     * Saves the user. This method will also set {@link Userx#createDate} for new
     * entities or {@link Userx#updateDate} for updated entities. The user
     * requesting this operation will also be stored as {@link Userx#createDate}
     * or {@link Userx#updateUser} respectively.
     *
     * @param user the user to save
     * @return the updated user
     */
    @PreAuthorize("hasAuthority('ADMIN')")
    public Userx saveUser(Userx user) {
        if (user.isNew()) {
            user.setCreateDate(new Date());
            user.setCreateUser(getAuthenticatedUser());
        } else {
            user.setUpdateDate(new Date());
            user.setUpdateUser(getAuthenticatedUser());
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    /**
     * Deletes the user.
     *
     * @param user the user to delete
     */
    @PreAuthorize("hasAuthority('ADMIN')")
    public void deleteUser(Userx user) throws IOException {
        //userRepository.delete(user);

        System.out.println("User deleted: " + user.getUsername());
        user.setDeleted(this.getAuthenticatedUser().getUsername());
        user.setDeletedDate(new Date());
        this.saveUser(user);

//        // :TODO: write some audit log stating who and when this user was permanently deleted.

    }

    private Userx getAuthenticatedUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return userRepository.findFirstByUsername(auth.getName());
    }
    @PreAuthorize("hasAuthority('ADMIN')")
    public Collection<Userx> getAllDeletedUsers() {
        return userRepository.findAllDeletedUsers();
    }
}
