package com.cecurity;

import java.time.Duration;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.StructuredTaskScope;
import java.util.concurrent.StructuredTaskScope.Subtask;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static com.cecurity.ConcurrentThreads.randomTask;

class CollectingJoiner<T> implements StructuredTaskScope.Joiner<T, Stream<T>> {

    private final Queue<T> results = new ConcurrentLinkedQueue<>();

    public boolean onComplete(Subtask<? extends T> subtask) {
        if (subtask.state() == Subtask.State.SUCCESS) {
            results.add(subtask.get());
        }
        return false;
    }

    public Stream<T> result() {
        System.out.println("Collected " + results.size() + " results");
        return results.stream();
    }
    static <T> List<T> allSuccessful(List<Callable<T>> tasks) throws InterruptedException {
        try (var scope = StructuredTaskScope.open(new CollectingJoiner<T>())) {
            tasks.forEach(scope::fork);
            return scope.join().toList();
        }
    }
    static void main(String[] args) {

        IO.println("------\nRunning CollectingJoiner");
        testCollectingJoiner();
        IO.println("------\nRunning Concurrently Configured Random Tasks");
        runConcurrentlyConfiguredRandomTasks();
        IO.println("------\nDone");
    }
    private static void testCollectingJoiner() {
        List<Callable<Integer>> subtasks = IntStream
                .range(0, 10)
                .mapToObj(_ -> (Callable<Integer>) () -> randomTask(1000, 200))
                .collect(Collectors.toList());

        try {
            allSuccessful(subtasks).forEach(r -> System.out.println("Result -> " + r));
        } catch (InterruptedException e) {
            Throwable cause = e.getCause();
            System.out.println("FailedException: " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
        }
    }
    static void runConcurrentlyConfiguredRandomTasks() {
        var subtasks = IntStream.range(0, 5)
                .mapToObj(i -> (Callable<Integer>) () -> randomTask(1000, 900))
                .collect(Collectors.toList());

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
        }
    }
}
