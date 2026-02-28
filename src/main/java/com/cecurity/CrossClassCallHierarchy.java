package com.cecurity;

import com.github.javaparser.*;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;

import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.*;

import com.github.javaparser.resolution.declarations.*;

import java.io.File;
import java.util.*;

public class CrossClassCallHierarchy {

    // Fully qualified caller → callees
    private static Map<String, Set<String>> callGraph =
            new LinkedHashMap<>();

    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            System.out.println(
                    "Usage: java CrossClassCallHierarchy <source-root>");
            return;
        }

        File sourceRoot = new File(args[0]);

        setupSymbolSolver(sourceRoot);

        parseProject(sourceRoot);

        System.out.println("\n=== CROSS CLASS CALL GRAPH ===\n");

        for (String method : callGraph.keySet()) {
            printHierarchy(method,
                    new HashSet<>(), 0);
        }
    }

    /**
     * Configure symbol solver
     */
    private static void setupSymbolSolver(File sourceRoot) {

        CombinedTypeSolver solver =
                new CombinedTypeSolver();

        solver.add(new ReflectionTypeSolver());
        solver.add(new JavaParserTypeSolver(sourceRoot));

        JavaSymbolSolver symbolSolver =
                new JavaSymbolSolver(solver);

        StaticJavaParser.getConfiguration()
                .setSymbolResolver(symbolSolver);
    }

    /**
     * Parse all java files
     */
    private static void parseProject(File dir)
            throws Exception {

        for (File file :
                Objects.requireNonNull(dir.listFiles())) {

            if (file.isDirectory()) {
                parseProject(file);
            }
            else if (file.getName()
                    .endsWith(".java")) {

                CompilationUnit cu =
                        StaticJavaParser.parse(file);

                new MethodVisitor()
                        .visit(cu, null);
            }
        }
    }

    /**
     * AST Visitor
     */
    private static class MethodVisitor
            extends VoidVisitorAdapter<Void> {

        @Override
        public void visit(MethodDeclaration md,
                          Void arg) {

            try {

                ResolvedMethodDeclaration resolved =
                        md.resolve();

                String caller =
                        resolved.getQualifiedSignature();

                callGraph.putIfAbsent(
                        caller,
                        new LinkedHashSet<>());

                md.findAll(MethodCallExpr.class)
                        .forEach(call -> {

                            try {

                                ResolvedMethodDeclaration callee =
                                        call.resolve();

                                String target =
                                        callee.getQualifiedSignature();

                                callGraph
                                        .get(caller)
                                        .add(target);

                            } catch (Exception ignored) {}
                        });

            } catch (Exception ignored) {}

            super.visit(md, arg);
        }
    }

    /**
     * Print hierarchy
     */
    private static void printHierarchy(
            String method,
            Set<String> visited,
            int indent) {

        if (visited.contains(method))
            return;

        visited.add(method);

        System.out.println(
                " ".repeat(indent) + method);

        for (String called :
                callGraph.getOrDefault(
                        method, Set.of())) {

            System.out.print(
                    " ".repeat(indent) + " └── ");

            printHierarchy(
                    called,
                    visited,
                    indent + 4);
        }
    }
}
