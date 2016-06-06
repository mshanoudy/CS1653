package userclient.gui.controller;


import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.stage.Stage;

public class ListMembersController
{
    @FXML private ListView<String> memberListView;

    private ObservableList<String> memberList = FXCollections.observableArrayList();

    private Stage  stage;
    private Main   mainApp;
    private String groupname;

    public ListMembersController()
    {
    }

    public void setControllers(Stage stage, Main mainApp)
    {
        this.stage   = stage;
        this.mainApp = mainApp;
    }

    public void setMemberList(String groupname)
    {
        // Set groupname
        this.groupname = groupname;
        // Add group members to list
        memberList.addAll(mainApp.groupClient.listMembers(groupname, mainApp.getUserToken()));
    }

    public void setMemberListView()
    {
        memberListView.setItems(memberList);
    }

    @FXML protected void handleCancelButtonAction()
    {
        stage.close();
    }

    @FXML protected void handleAddMemberButtonAction() throws Exception
    {
        // Get member name
        String membername = mainApp.showInputDialog("User Name");
        // Try to add member
        if (!mainApp.groupClient.addUserToGroup(membername, groupname, mainApp.getUserToken()))
            mainApp.showMessageDialog("Error adding member");
        else
            memberList.add(membername);
    }

    @FXML protected void handleDeleteMemberButtonAction() throws Exception
    {
        // Get selected member
        String membername = memberListView.getSelectionModel().getSelectedItem();
        // Try to delete member
        if (!mainApp.groupClient.deleteUserFromGroup(membername, groupname, mainApp.getUserToken()))
            mainApp.showMessageDialog("Error removing member");
        else
            memberList.remove(membername);
    }

}
