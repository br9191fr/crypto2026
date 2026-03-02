package com.cecurity;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class CallHierarchyGenerator {

    // method -> called methods
    private static Map<String, Set<String>> callGraph = new HashMap<>();

    // regex patterns
    private static final Pattern METHOD_DECL =
            Pattern.compile("\\b(?:public|private|protected)?\\s*(?:static)?\\s*\\w+\\s+(\\w+)\\s*\\(");

    private static final Pattern METHOD_CALL =
            Pattern.compile("\\b(\\w+)\\s*\\(");

    public static void main(String[] args) throws IOException {

        if (args.length == 0) {
            System.out.println("Usage: java CallHierarchyGenerator <JavaFile>");
            return;
        }
        var p = Paths.get(args[0]);
        List<String> lines = Files.readAllLines(p);
        //List<String> lines = Files.readAllLines(Paths.get(args[0]));

        buildCallGraph(lines);

        System.out.println("\n=== Call Hierarchy ===\n");

        for (String method : callGraph.keySet()) {
            printHierarchy(method, new HashSet<>(), 0);
        }
    }

    private static void buildCallGraph(List<String> lines) {

        String currentMethod = null;
        int braceDepth = 0;

        for (String line : lines) {

            Matcher declMatcher = METHOD_DECL.matcher(line);

            // detect method declaration
            if (declMatcher.find()) {
                currentMethod = declMatcher.group(1);
                callGraph.putIfAbsent(currentMethod, new LinkedHashSet<>());
                braceDepth = 0;
            }

            if (currentMethod != null) {

                braceDepth += count(line, '{');
                braceDepth -= count(line, '}');

                Matcher callMatcher = METHOD_CALL.matcher(line);

                while (callMatcher.find()) {
                    String called = callMatcher.group(1);

                    if (!called.equals(currentMethod)
                            && !isKeyword(called)) {

                        callGraph
                                .get(currentMethod)
                                .add(called);
                    }
                }

                if (braceDepth <= 0) {
                    currentMethod = null;
                }
            }
        }
    }

    private static void printHierarchy(
            String method,
            Set<String> visited,
            int indent) {

        if (visited.contains(method))
            return;

        visited.add(method);

        System.out.println(" ".repeat(indent) + method);

        for (String called :
                callGraph.getOrDefault(method, Set.of())) {

            System.out.print(" ".repeat(indent) + " └── ");
            printHierarchy(called, visited, indent + 4);
        }
    }

    private static int count(String line, char c) {
        int cnt = 0;
        for (char ch : line.toCharArray())
            if (ch == c) cnt++;
        return cnt;
    }

    private static boolean isKeyword(String name) {
        return Set.of(
                "if", "for", "while", "switch",
                "catch", "return", "new", "throw"
        ).contains(name);
    }
}

