package userclient.gui.controller;

import javafx.fxml.FXML;
import javafx.scene.control.MenuItem;

public class RootLayoutController
{
    @FXML private MenuItem disconnectMenuItem;
    @FXML private MenuItem createUserMenuItem;
    @FXML private MenuItem deleteUserMenuItem;

    private Main mainApp;

    public void setMainApp(Main mainApp)
    {
        this.mainApp = mainApp;
    }

    public void setMenuItemsVivibility()
    {
        disconnectMenuItem.setVisible(true);
        if (mainApp.getUserToken().getGroups().contains("ADMIN"))
        {// Check if ADMIN
            createUserMenuItem.setVisible(true);
            deleteUserMenuItem.setVisible(true);
        }
    }

    @FXML protected void handleDisconnectMenuItemAction()
    {
        mainApp.groupClient.disconnect();
        mainApp.fileClient.disconnect();

        System.exit(0);
    }

    @FXML protected void handleCreateUserMenuItemAction() throws Exception
    {
        String username = mainApp.showInputDialog("User Name");
        String password = mainApp.showInputDialog("User Password");

        if (mainApp.groupClient.createUser(username, password, mainApp.getUserToken()))
            mainApp.showMessageDialog("User: " + username + " created");
        else
            mainApp.showMessageDialog("Error creating user");
    }

    @FXML protected void handleDeleteUserMenuItemAction() throws Exception
    {
        String username = mainApp.showInputDialog("User name");

        if (mainApp.groupClient.deleteUser(username, mainApp.getUserToken()))
            mainApp.showMessageDialog("User: " + username + " deleted");
        else
            mainApp.showMessageDialog("Error deleting user");
    }
}
