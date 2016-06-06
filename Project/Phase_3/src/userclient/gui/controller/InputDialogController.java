package userclient.gui.controller;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.stage.Stage;

/**
 * Controller for InputDialog
 * Creates a dialog box which displays message and accepts user input
 */
public class InputDialogController
{
    @FXML private Label inputDialogLabel;
    @FXML private TextField inputTxtFld;

    private Stage stage;

    /**
     * Sets the stage for this scene
     *
     * @param stage The stage
     */
    public void setDialogStage(Stage stage)
    {
        this.stage = stage;
    }

    /**
     * Gets the user input
     *
     * @return The user input
     */
    public String getInputTxtFld()
    {
        return inputTxtFld.getText();
    }

    /**
     * Sets the message label
     *
     * @param message The message
     */
    public void setInputDialogLabel(String message)
    {
        inputDialogLabel.setText(message);
    }

    /**
     * Closes the window
     */
    @FXML protected void handleOKButtonAction()
    {
        stage.close();
    }

    /**
     * Cancels the input
     */
    @FXML protected void handleCancelButton()
    {
        inputTxtFld.clear();

        stage.close();
    }
}
