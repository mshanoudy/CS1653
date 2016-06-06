package userclient.gui.controller;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.stage.Stage;

public class MessageDialogController
{
    @FXML private Label messageDialogLabel;

    private Stage stage;

    public MessageDialogController()
    {
    }

    public void setDialogStage(Stage stage)
    {
        this.stage = stage;
    }

    public void setMessageDialogLabel(String message)
    {
        messageDialogLabel.setText(message);
    }

    @FXML protected void handleCloseButtonAction()
    {
        stage.close();
    }
}
