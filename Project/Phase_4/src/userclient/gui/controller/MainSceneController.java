package userclient.gui.controller;

import javafx.fxml.FXML;
import javafx.scene.control.ListView;
import javafx.scene.control.TreeItem;
import javafx.scene.control.TreeView;
import javafx.scene.input.*;
import userclient.gui.model.FilePathTreeItem;

import javax.crypto.SecretKey;
import java.io.File;

/**
 * Controller for MainScene
 * Handles the majority of the user commands
 */
public class MainSceneController
{
    @FXML private ListView<String> groupListView;
    @FXML private TreeView<String> localFileTreeView;
    @FXML private TreeView<String> serverFileTreeView;

    private Main mainApp;

    // FilePathTreeItem to help with generating TreeViews
    private FilePathTreeItem pathItem = new FilePathTreeItem();

    /**
     * Sets the reference to Main
     * First thing called when scene is shown
     *
     * @param mainApp The main class
     */
    public void setMainApp(Main mainApp)
    {
        // Set reference to Main
        this.mainApp = mainApp;

        // Set groupListView
        groupListView.setItems(mainApp.getGroupList());

        // Set localFileTreeView and serverFileTreeView
        updateLocalTree();
        updateServerTree();
    }

    /**
     * Updates the serverFileTreeView
     */
    private void updateServerTree()
    {
        TreeItem<String> serverRootNode = pathItem.buildServerTreeRoot(mainApp.fileClient.listFiles(mainApp.getUserToken()));
        serverRootNode.setExpanded(true);
        serverFileTreeView.setRoot(serverRootNode);
    }

    /**
     * Updates the localFileTreeView
     */
    private void updateLocalTree()
    {
        TreeItem<String> localRootNode = pathItem.buildLocalTreeRoot(new File("."));
        localRootNode.setExpanded(true);
        localFileTreeView.setRoot(localRootNode);
    }

    /**
     * Generates the file path based on parent nodes in TreeView
     *
     * @param selectedFile The selected file
     * @return The path name
     */
    private String getFilePath(TreeItem<String> selectedFile)
    {
        StringBuilder string = new StringBuilder();

        // Append filename first
        string.append(selectedFile.getValue());

        // Insert parent directories into path
        TreeItem<String> treeItem = selectedFile;
        while ( (treeItem = treeItem.getParent()) != null )
            string.insert(0, treeItem.getValue() + "/");

        return string.toString();
    }

    /**
     * Handles adding a group
     *
     * @throws Exception
     */
    @FXML protected void handleAddGroupButtonAction() throws Exception
    {
        // Get the groupname
        String groupname = mainApp.showInputDialog("Group Name");
        // Try to create group
        if ((!mainApp.groupClient.createGroup(groupname, mainApp.getUserToken())) || groupname.equals(""))
            mainApp.showMessageDialog("Error creating group");
        else // Update groupListView
            mainApp.getGroupList().add(groupname);
    }

    /**
     * Handles deleting a group
     *
     * @throws Exception
     */
    @FXML protected void handleDeleteGroupButtonAction() throws Exception
    {
        // Get the selected group
        String groupname = groupListView.getSelectionModel().getSelectedItem();
        // Try to delete group
        if (!mainApp.groupClient.deleteGroup(groupname, mainApp.getUserToken()))
            mainApp.showMessageDialog("Error deleting group");
        else // Update groupListView
            mainApp.getGroupList().remove(groupname);
    }

    /**
     * Handles launching ListMembersDialog if sufficient permission to do so
     *
     * @throws Exception
     */
    @FXML protected void handleListMembersButtonAction() throws Exception
    {
        // Get the selected group
        String groupname = groupListView.getSelectionModel().getSelectedItem();
        // Check if member list is null, if null user not owner
        if (mainApp.groupClient.listMembers(groupname, mainApp.getUserToken()) == null)
            mainApp.showMessageDialog("Insufficient Permission");
        else
            mainApp.showListMembersDialog(groupname);
    }

    /**
     * Handles deleting a file on the FileServer
     *
     * @throws Exception
     */
    @FXML protected void handleDeleteFileButtonAction() throws Exception
    {
        // Construct the full pathname to file on server
        String remotePath = getFilePath(serverFileTreeView.getSelectionModel().getSelectedItem());

        // Try to delete the file
        if (mainApp.fileClient.delete(remotePath, mainApp.getUserToken()))
            updateServerTree();
        else
            mainApp.showMessageDialog("Error deleting file");
    }

    /**
     * Handles first event in upload drag-and-drop
     *
     * @param mouseEvent The user drags a file from source
     */
    @FXML protected void handleLocalFileTreeViewOnDragDetected(MouseEvent mouseEvent)
    {
        // Drag was detected, start a drag-and-drop gesture
        // Allow copy transfer mode
        Dragboard dragboard = localFileTreeView.startDragAndDrop(TransferMode.COPY);

        // Put file path on the dragboard
        ClipboardContent content = new ClipboardContent();
        content.putString(getFilePath(localFileTreeView.getSelectionModel().getSelectedItem()));
        dragboard.setContent(content);

        mouseEvent.consume();
    }

    /**
     * Handles second event in upload drag-and-drop
     *
     * @param dragEvent The user drags file over target
     */
    @FXML protected void handleServerFileTreeViewOnDragOver(DragEvent dragEvent)
    {
        // Data is dragged over the target
        // Accepts only if not dragged from same node and is a String
        if (dragEvent.getGestureSource() != serverFileTreeView &&
            dragEvent.getDragboard().hasString())
            dragEvent.acceptTransferModes(TransferMode.COPY);

        dragEvent.consume();
    }

    /**
     * Handles last event in upload drag-and-drop
     * Attempts to upload selected file
     *
     * @param dragEvent The user releases the file
     * @throws Exception
     */
    @FXML protected void handleServerFileTreeViewOnDragDropped(DragEvent dragEvent) throws Exception
    {
        // Data dropped
        // Read string from dragboard
        Dragboard dragboard = dragEvent.getDragboard();

        if (dragboard.hasString())
        {// If upload successful
            if (mainApp.fileClient.upload(dragboard.getString(),
                                          mainApp.showInputDialog("File Name on Server"),
                                          groupListView.getSelectionModel().getSelectedItem(),
                                          (SecretKey)mainApp.groupClient.getGroupKey(groupListView.getSelectionModel().getSelectedItem(), mainApp.getUserToken()).get(0),
                                          (byte[])mainApp.groupClient.getGroupKey(groupListView.getSelectionModel().getSelectedItem(), mainApp.getUserToken()).get(1),
                                          mainApp.getUserToken()))
            {// Update the server tree to reflect upload
                updateServerTree();
                dragEvent.setDropCompleted(true);
            }
            else
            {// Failed upload
                mainApp.showMessageDialog("Error uploading file");
                dragEvent.setDropCompleted(false);
            }
        }

        dragEvent.consume();
    }

    /**
     * Handles event where upload was successful
     * Unused as of now
     *
     * @param dragEvent Upload was successful
     */
    @FXML protected void handleLocalFileTreeViewOnDragDone(DragEvent dragEvent)
    {
        // The drag and drop gesture has ended
        // Do nothing for now

        dragEvent.consume();
    }

    /**
     * Handles first event in download drag-and-drop
     *
     * @param mouseEvent The user drags a file from source
     */
    @FXML protected void handleServerFileTreeViewOnDragDetected(MouseEvent mouseEvent)
    {
        // Drag was detected, start a drag-and-drop gesture
        // Allow copy transfer mode
        Dragboard dragboard = serverFileTreeView.startDragAndDrop(TransferMode.COPY);

        // Put file path on the dragboard
        ClipboardContent content = new ClipboardContent();
        content.putString(getFilePath(serverFileTreeView.getSelectionModel().getSelectedItem()));
        dragboard.setContent(content);

        mouseEvent.consume();
    }

    /**
     * Handles second event in download drag-and-drop
     *
     * @param dragEvent The user drags file over target
     */
    @FXML protected void handleLocalFileTreeViewOnDragOver(DragEvent dragEvent)
    {
        // Data is dragged over the target
        // Accepts only if not dragged from same node and is a String
        if (dragEvent.getGestureSource() != localFileTreeView &&
            dragEvent.getDragboard().hasString())
            dragEvent.acceptTransferModes(TransferMode.COPY);

        dragEvent.consume();
    }

    /**
     * Handles last event in download drag-and-drop
     * Attempts to download selected file
     *
     * @param dragEvent The user releases the file
     * @throws Exception
     */
    @FXML protected void handleLocalFileTreeViewOnDragDropped(DragEvent dragEvent) throws Exception
    {
        // Data dropped
        // Read string from dragboard
        Dragboard dragboard = dragEvent.getDragboard();

        String groupname = dragboard.getString().split("/")[1];

        if (dragboard.hasString())
        {// If upload successful
            if (mainApp.fileClient.download(dragboard.getString(),
                                            mainApp.showInputDialog("File Name"),
                                            (SecretKey)mainApp.groupClient.getGroupKey(groupname, mainApp.getUserToken()).get(0),
                                            (byte[])mainApp.groupClient.getGroupKey(groupname, mainApp.getUserToken()).get(1),
                                            mainApp.getUserToken()))
            {// Update the local tree to reflect upload
                updateLocalTree();
                dragEvent.setDropCompleted(true);
            }
            else
            {// Failed upload
                mainApp.showMessageDialog("Error uploading file");
                dragEvent.setDropCompleted(false);
            }
        }

        dragEvent.consume();
    }

    /**
     * Handles event where download was successful
     * Unused as of now
     *
     * @param dragEvent Download was successful
     */
    @FXML protected void handleServerFileTreeViewOnDragDone(DragEvent dragEvent)
    {
        // The drag and drop gesture has ended
        // Do nothing for now

        dragEvent.consume();
    }
}
