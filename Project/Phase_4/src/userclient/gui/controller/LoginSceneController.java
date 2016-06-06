package userclient.gui.controller;

import javafx.fxml.FXML;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import server.UserToken;

import java.security.SignedObject;

/**
 * Controller for LoginScene
 * Attempts to log into servers using a username defined by client user
 */
public class LoginSceneController
{
    @FXML private TextField userNameTxtFld;
    @FXML private PasswordField passwordField;
    @FXML private TextField groupServerNameTxtFld;
    @FXML private TextField groupServerPortTxtFld;
    @FXML private TextField fileServerNameTxtFld;
    @FXML private TextField fileServerPortTxtFld;

    private Main mainApp; // Reference to Main

    /**
     * Sets the reference to Main
     *
     * @param mainApp The main class
     */
    public void setMainApp(Main mainApp)
    {
        this.mainApp = mainApp;
    }

    /**
     * Logs the user in
     *
     * @throws Exception
     */
    @FXML protected void handleLoginButtonAction() throws Exception
    {// Tries to establish connection with servers
        if (mainApp.groupClient.connect(groupServerNameTxtFld.getText(),
                                        Integer.parseInt(groupServerPortTxtFld.getText())) &&
            mainApp.fileClient.connect(fileServerNameTxtFld.getText(),
                                       Integer.parseInt(fileServerPortTxtFld.getText())))
        {// Perform handshakes
            if (!mainApp.groupClient.handshake())
                mainApp.showMessageDialog("Problem with GroupServer handshake");
            if (!mainApp.fileClient.handshake(mainApp.groupClient.getPublicKey()))
                mainApp.showMessageDialog("Problem with FileServer handshake");

            // Set password and fileServerID for GroupClient
            mainApp.groupClient.setPassword(passwordField.getText());
            mainApp.groupClient.setFileServerID(mainApp.fileClient.getFileServerID());

            // Get token
            SignedObject token = mainApp.groupClient.getToken(userNameTxtFld.getText());

            if (token != null)
            {// Set token and show MainScene
                mainApp.setUserToken(token);
                mainApp.showMainScene();
            }
            else // User does not exist
                mainApp.showMessageDialog("Problem getting token");
        }
        else // No server connection
            mainApp.showMessageDialog("Problem connecting to servers");
    }
}
