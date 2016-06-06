package userclient.gui.controller;

import javafx.fxml.FXML;
import javafx.scene.control.MenuItem;
import server.UserToken;

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
        try
        {
            disconnectMenuItem.setVisible(true);

            // Work around that should be replaced by proper method in GroupClient
            UserToken token = (UserToken)mainApp.getUserToken().getObject();

            if (token.getGroups().contains("ADMIN"))
            {// Check if ADMIN
                createUserMenuItem.setVisible(true);
                deleteUserMenuItem.setVisible(true);
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
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
