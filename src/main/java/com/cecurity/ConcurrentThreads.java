package com.cecurity;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.lang.ScopedValue;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.StructuredTaskScope.Subtask;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class ConcurrentThreads {
    private static final List<String> sharedList = new ArrayList<>();
    private static final ScopedValue<String> NAME = ScopedValue.newInstance();

    static final Callable<String> task1 = () -> { return "Hello World"; };
    static final Callable<Integer> task2 = () -> { return 42; };

    static void main() {
        step1();
        step2();
        runConcurrentlyConfiguredRandomTasks();
        IO.println("Done");
    }

    private static void step1() {
        System.out.println("Starting step1");
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {

            for (int i = 0; i < 3; i++) {
                int taskId = i;
                executor.submit(() -> {
                    addItem("Item from task " + taskId);
                    System.out.println("Item added from task " + taskId);
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    }
                    addItem("Item from task " + taskId);
                });
            }
        }
        catch (Exception e) {
            System.err.println("Error occurred while processing tasks: " + e.getMessage());
        }
        ScopedValue.where(NAME, "duke1").run( () -> addInfo());
        System.out.println("Final list: " + sharedList);
        System.out.println("Finished step1");
    }

    /**
     * Helper method for step2 to demonstrate StructuredTaskScope usage
     * This method showcases how to use StructuredTaskScope to manage multiple tasks concurrently,
     * handling exceptions, and retrieving results from subtasks.
     */
    private static void step2() {
        System.out.println("Starting step2");
        // Open a new StructuredTaskScope
        try (var scope = StructuredTaskScope.open()) {
            // Fork subtasks
            Subtask<String> subtask1 = scope.fork(task1);
            Subtask<Integer> subtask2 = scope.fork(task2);

            // Join the scope's subtasks and propagate exceptions
            scope.join();

            // Process the join method's results
            System.out.println("subtask1: " + subtask1.get());
            System.out.println("subtask2: " + subtask2.get());

        } catch (InterruptedException e) {
            System.out.println("InterruptedException");
        }
        System.out.println("Finished step2");
    }
    private static synchronized void addItem(String value) {
        sharedList.add(value);
    }
    private static synchronized void addInfo() {
        sharedList.add("OK");
    }
    private static void runConcurrentlyConfiguredRandomTasks() {
        var subtasks = IntStream.range(0, 5)
                .mapToObj(_ -> (Callable<Integer>) () -> randomTask(1000, 700))
                .toList();

        try (var scope = StructuredTaskScope.open(StructuredTaskScope.Joiner.<Integer>allSuccessfulOrThrow(),
                cf -> cf.withTimeout(Duration.ofMillis(1000)))) {
            subtasks.forEach(scope::fork);
            Stream<Subtask<Integer>> s = scope.join();
            s.forEach(r -> System.out.println("Result: " + r.get()));
        } catch (InterruptedException e) {
            System.out.println("InterruptedException");
        } catch (StructuredTaskScope.TimeoutException e) {
            System.out.println("TimeoutException");
        } catch (StructuredTaskScope.FailedException e) {
            Throwable cause = e.getCause();
            System.out.println("FailedException: " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
            throw new RuntimeException(cause);
        }
    }
    static Integer randomTask(int maxDuration, int threshold) throws InterruptedException, TooSlowException {
        int t = new Random().nextInt(maxDuration);
        if (t > threshold) {
            throw new TooSlowException("Duration " + t + " greater than threshold " + threshold);
        }
        Thread.sleep(t);
        System.out.println("Task duration -> " + t);
        return t;
    }
    static class TooSlowException extends Exception {
        public TooSlowException(String s) {
            super(s);
        }
    }
}
