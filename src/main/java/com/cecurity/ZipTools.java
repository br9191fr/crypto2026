package com.cecurity;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

class Node {
    public String name;
    public String type; // "directory" or "file"
    public Long size;   // null for directory
    public List<Node> children;

    public Node(String name, String type) {
        this.name = name;
        this.type = type;
        if (type.equals("directory")) {
            children = new ArrayList<>();
        }
    }
}
public class ZipTools {

    public static void main(String[] args) throws Exception {
        System.out.println("Starting ZipTools");
        if (args.length == 0) {
            System.out.println("Usage: java ZipTools <zipFilePath> <outputJsonPath>");
            return ;
        }
        if (args.length != 2) {
            System.out.println("Usage: java ZipTools <zipFilePath> <outputJsonPath>");
            return;
        }
        String zipFilePath = args[0];
        String outputJsonPath = args[1];

        Node root = new Node("root", "directory");

        Map<String, Node> directoryMap = new HashMap<>();
        directoryMap.put("", root);
        System.out.println("Starting really");
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFilePath))) {
            ZipEntry entry;
            //final Enumeration<? extends ZipEntry> entries = zis.entries();
            while ((entry = zis.getNextEntry()) != null) {
            //while (entries.hasMoreElements()) {
                //final ZipEntry entry = entries.nextElement();
                String entryName = entry.getName();
                String[] parts = entryName.split("/");

                StringBuilder currentPath = new StringBuilder();
                Node parent = root;

                for (int i = 0; i < parts.length; i++) {
                    String part = parts[i];
                    currentPath.append(part);

                    boolean isLast = (i == parts.length - 1);

                    if (isLast && !entry.isDirectory()) {
                        Node fileNode = new Node(part, "file");
                        var lg = entry.getCompressedSize();
                        System.out.println("Longueur :" + lg);
                        fileNode.size = entry.getSize();
                        parent.children.add(fileNode);
                    } else {
                        currentPath.append("/");
                        String pathKey = currentPath.toString();

                        if (!directoryMap.containsKey(pathKey)) {
                            Node dirNode = new Node(part, "directory");
                            parent.children.add(dirNode);
                            directoryMap.put(pathKey, dirNode);
                        }

                        parent = directoryMap.get(pathKey);
                    }
                }
            }
        }
        System.out.println("Saving JSON");
        ObjectMapper mapper = new ObjectMapper();
        mapper.enable(SerializationFeature.INDENT_OUTPUT);
        mapper.writeValue(new File(outputJsonPath), root);

        System.out.println("JSON généré avec succès : " + outputJsonPath);
    }
}
