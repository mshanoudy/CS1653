package userclient.gui.model;

import javafx.scene.control.TreeItem;

import java.io.File;
import java.util.*;

/**
 * Class that handles building the TreeItems for TreeViews used in MainScene
 */
public class FilePathTreeItem extends TreeItem<String>
{
    /**
     * Builds the root node for localFileTreeView
     *
     * @param dir The starting directory
     *
     * @return The root node
     */
    public TreeItem<String> buildLocalTreeRoot(File dir)
    {
        // Create node and directory
        TreeItem<String> rootNode = new TreeItem<>(dir.getName());
        File directory = new File(dir.getPath());

        // Get all the files from directory
        File[] fileList = directory.listFiles();

        for (File file : fileList)
        {// Iterate over files in directory and add to root
            if (file.isFile())           // Is a file
                rootNode.getChildren().add(new TreeItem<>(file.getName()));
            else if (file.isDirectory()) // Is directory
                rootNode.getChildren().add(buildLocalTreeRoot(file));
        }

        return rootNode;
    }

    /**
     * Builds the root node for serverFileTreeView
     *
     * @param fileList The list of files on the file server
     *
     * @return The root node
     */
    public TreeItem<String> buildServerTreeRoot(List<String> fileList)
    {
        // Create node and sort fileList
        TreeItem<String> rootNode = new TreeItem<>("shared_files");
        Collections.sort(fileList);

        if (!fileList.isEmpty())
        {// Fix for Windows path names
            if (fileList.get(0).contains("\\"))
                fileList = fixPathSlashes(fileList);

            // Get the first group directory name and set group node
            String groupName  = fileList.get(0).split("/")[1];
            TreeItem<String> groupNode = new TreeItem<>(groupName);

            for (String file : fileList)
            {// Iterate over fileList from file server
                // File is in current group
                if (file.split("/")[1].equals(groupName))
                    groupNode.getChildren().add(new TreeItem<>(file.split("/")[2]));
                else
                {// File is in next group
                    rootNode.getChildren().add(groupNode); // Add the current group node
                    groupName = file.split("/")[1];        // Get new groupName
                    groupNode = new TreeItem<>(groupName); // Create new groupNode
                    // Add file to groupNode
                    groupNode.getChildren().add(new TreeItem<>(file.split("/")[2]));
                }
            }
            // Add final groupNode
            rootNode.getChildren().add(groupNode);

            return rootNode;
        }
        else // Empty directory
            return rootNode;
    }

    /**
     * Replaces the '\' char with '/'
     *
     * @param fileList The list of files on the file server
     *
     * @return The fixed list of files
     */
    private List<String> fixPathSlashes(List<String> fileList)
    {
        List<String> list = new ArrayList<>();

        for (String file : fileList)
            list.add(file.replace("\\", "/"));
        return list;
    }
}
