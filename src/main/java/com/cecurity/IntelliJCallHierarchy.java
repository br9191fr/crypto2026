package com.cecurity;


import com.github.javaparser.*;
import com.github.javaparser.ast.*;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.*;

import com.github.javaparser.resolution.declarations.*;

import java.io.File;
import java.util.*;

public class IntelliJCallHierarchy {

    // caller -> callees
    private static Map<String, Set<String>> outgoing =
            new HashMap<>();

    // callee -> callers
    private static Map<String, Set<String>> incoming =
            new HashMap<>();

    public static void main(String[] args) throws Exception {

        if (args.length < 2) {
            System.out.println(
                    "Usage: java IntelliJCallHierarchy <srcRoot> <methodName>");
            return;
        }

        File srcRoot = new File(args[0]);
        String targetMethod = args[1];

        setupSolver(srcRoot);
        scan(srcRoot);

        System.out.println("\n===== OUTGOING CALLS =====\n");
        printTree(targetMethod, outgoing,
                new HashSet<>(), 0);

        System.out.println("\n===== INCOMING CALLS =====\n");
        printTree(targetMethod, incoming,
                new HashSet<>(), 0);
    }

    /**
     * Symbol Solver setup
     */
    private static void setupSolver(File root) {

        CombinedTypeSolver solver =
                new CombinedTypeSolver();

        solver.add(new ReflectionTypeSolver());
        solver.add(new JavaParserTypeSolver(root));

        JavaSymbolSolver symbolSolver =
                new JavaSymbolSolver(solver);

        StaticJavaParser.getConfiguration()
                .setSymbolResolver(symbolSolver);
    }

    /**
     * Scan project recursively
     */
    private static void scan(File dir)
            throws Exception {

        for (File file :
                Objects.requireNonNull(dir.listFiles())) {

            if (file.isDirectory())
                scan(file);

            else if (file.getName()
                    .endsWith(".java")) {

                CompilationUnit cu =
                        StaticJavaParser.parse(file);

                new Visitor().visit(cu, null);
            }
        }
    }

    /**
     * AST Visitor
     */
    private static class Visitor
            extends VoidVisitorAdapter<Void> {

        @Override
        public void visit(MethodDeclaration md,
                          Void arg) {

            try {

                String caller =
                        md.resolve()
                                .getQualifiedSignature();

                outgoing.putIfAbsent(
                        caller,
                        new HashSet<>());

                md.findAll(MethodCallExpr.class)
                        .forEach(call -> {

                            try {

                                String callee =
                                        call.resolve()
                                                .getQualifiedSignature();

                                outgoing
                                        .get(caller)
                                        .add(callee);

                                incoming
                                        .computeIfAbsent(
                                                callee,
                                                k -> new HashSet<>())
                                        .add(caller);

                            } catch (Exception ignored) {}
                        });

            } catch (Exception ignored) {}

            super.visit(md, arg);
        }
    }

    /**
     * Tree printer
     */
    private static void printTree(
            String method,
            Map<String, Set<String>> graph,
            Set<String> visited,
            int indent) {

        if (visited.contains(method))
            return;

        visited.add(method);

        System.out.println(
                " ".repeat(indent) + method);

        for (String next :
                graph.getOrDefault(
                        method, Set.of())) {

            System.out.print(
                    " ".repeat(indent) + " └── ");

            printTree(next,
                    graph,
                    visited,
                    indent + 4);
        }
    }
}
