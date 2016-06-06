package userclient.gui.controller;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.stage.Modality;
import javafx.stage.Stage;
import server.FileClient;
import server.GroupClient;
import server.UserToken;

/**
 * Main class that controls the GUI User Client
 */
public class Main extends Application
{
    private Stage                primaryStage;         // Primary application stage
    private BorderPane           root;                 // The root layout
    private RootLayoutController rootLayoutController; // Controller for root layout
    private UserToken            userToken;            // Token for this user

    public GroupClient groupClient = new GroupClient();// The groupClient
    public FileClient  fileClient  = new FileClient(); // The fileClient

    // List that holds the groups of this user TODO: Move this into MainSceneController eventually
    private ObservableList<String> groupList = FXCollections.observableArrayList();

    /**
     * Runs the program.
     * Creates and displays stage, root layout, and login
     *
     * @param primaryStage The primary stage
     * @throws Exception
     */
    public void start(Stage primaryStage) throws Exception
    {
        // Set primary stage
        this.primaryStage = primaryStage;

        // Load the root layout
        showRootLayout();

        // Set stage title, set root scene, and show stage
        primaryStage.setTitle("User Client Application");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();

        // Show LoginDialog
        showLoginDialog();
    }

    /**
     * Gets primaryStage
     *
     * @return The primary stage
     */
    public Stage getPrimaryStage()
    {
        return primaryStage;
    }

    /**
     * Sets the userToken
     * Only called by LoginDialogController during initial login
     *
     * @param userToken The userToken
     */
    public void setUserToken (UserToken userToken)
    {
        this.userToken = userToken;
    }

    /**
     * Gets the userToken
     * Updates the token on call
     *
     * @return The userToken
     */
    public UserToken getUserToken()
    {
        userToken = groupClient.getToken(userToken.getSubject());
        return userToken;
    }

    /**
     * Gets the group list for this user
     *
     * @return The group list
     */
    public ObservableList<String> getGroupList()
    {
        return groupList;
    }

    /**
     * Shows the root layout
     *
     * @throws Exception
     */
    public void showRootLayout() throws Exception
    {
        // Load the root layout
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/userclient/gui/view/RootLayout.fxml"));
        root = (BorderPane) loader.load();

        // Give controller reference to Main
        rootLayoutController = loader.getController();
        rootLayoutController.setMainApp(this);
    }

    /**
     * Shows the login dialog
     *
     * @throws Exception
     */
    public void showLoginDialog() throws Exception
    {
        // Load FXML file and set as node on root
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/userclient/gui/view/LoginScene.fxml"));
        root.setCenter((AnchorPane) loader.load());

        // Give controller reference to Main
        LoginSceneController controller = loader.getController();
        controller.setMainApp(this);
    }

    /**
     * Shows the main scene
     *
     * @throws Exception
     */
    public void showMainScene() throws Exception
    {
        // Load FXML file and set as node on root
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/userclient/gui/view/MainScene.fxml"));
        root.setCenter((AnchorPane) loader.load());

        // Set group list
        groupList.addAll(userToken.getGroups());

        // Set root menu options
        rootLayoutController.setMenuItemsVivibility();

        // Give controller reference to Main
        MainSceneController controller = loader.getController();
        controller.setMainApp(this);
    }

    /**
     * Shows the list members dialog
     *
     * @param groupname The groupname to list members of
     * @throws Exception
     */
    public void showListMembersDialog(String groupname) throws Exception
    {
        // Load FXML file and create stage for dialog box
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/userclient/gui/view/ListMembersDialog.fxml"));
        Stage stage = new Stage();

        // Set stage properties and set scene
        stage.setTitle(groupname + " Member List");
        stage.initModality(Modality.WINDOW_MODAL);
        stage.initOwner(primaryStage);
        stage.setScene(new Scene((AnchorPane) loader.load()));

        // Give controller reference to stage, main, and pass groupname
        ListMembersController controller = loader.getController();
        controller.setControllers(stage, this);
        controller.setMemberList(groupname); // pass the groupname
        controller.setMemberListView();      // set the control

        // Show and wait until user closes
        stage.showAndWait();
    }

    /**
     * Shows a message dialog
     *
     * @param message The message to display
     * @throws Exception
     */
    public void showMessageDialog(String message) throws Exception
    {
        // Load FXML file and create stage for dialog box
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/userclient/gui/view/MessageDialog.fxml"));
        Stage stage = new Stage();

        // Set stage and set scene
        stage.initModality(Modality.WINDOW_MODAL);
        stage.initOwner(primaryStage);
        stage.setScene(new Scene((AnchorPane) loader.load()));

        // Give controller reference to stage
        MessageDialogController controller = loader.getController();
        controller.setDialogStage(stage);
        controller.setMessageDialogLabel(message);

        // Show and wait until user closes
        stage.showAndWait();
    }

    /**
     * Shows an input dialog
     *
     * @param message The message to display
     * @return The user input
     * @throws Exception
     */
    public String showInputDialog(String message) throws Exception
    {
        // Load FXML file and create stage for dialog box
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/userclient/gui/view/InputDialog.fxml"));
        Stage stage = new Stage();

        // Set stage and set scene
        stage.initModality(Modality.WINDOW_MODAL);
        stage.initOwner(primaryStage);
        stage.setScene(new Scene((AnchorPane) loader.load()));

        // Give controller reference to stage
        InputDialogController controller = loader.getController();
        controller.setDialogStage(stage);
        controller.setInputDialogLabel(message);

        // Show and wait until user closes
        stage.showAndWait();

        // Return the createTxtFld
        return controller.getInputTxtFld();
    }

    /**
     * Launches program
     *
     * @param args Unused command line argument
     */
    public static void main(String[] args)
    {
        launch(args);
    }
}
