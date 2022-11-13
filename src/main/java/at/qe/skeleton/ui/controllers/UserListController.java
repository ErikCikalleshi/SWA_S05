package at.qe.skeleton.ui.controllers;

import at.qe.skeleton.model.Userx;
import at.qe.skeleton.services.UserxService;
import java.io.Serializable;
import java.util.Collection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

/**
 * Controller for the user list view.
 *
 * This class is part of the skeleton project provided for students of the
 * course "Software Architecture" offered by Innsbruck University.
*/
@Component
@Scope("view")
public class UserListController implements Serializable {

    @Autowired
    private UserxService userService;

    /**
     * Returns a list of all users.
     *
     * @return
     */
    public Collection<Userx> getUsers() {
        return userService.getAllUsers();
    }

    /**
     * Returns a list of all delted users.
     *
     * @return
     */
    public Collection<Userx> getDeletedUsers() {
        return userService.getAllDeletedUsers();
    }
}
