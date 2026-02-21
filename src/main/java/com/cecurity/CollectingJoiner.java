package com.cecurity;

import java.util.List;
import java.util.Queue;
import java.lang.ScopedValue;
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
    public static void main(String[] args) {
        testCollectingJoiner();
    }
    private static void testCollectingJoiner() {
        List<Callable<Integer>> subtasks = IntStream
                .range(0, 10)
                .mapToObj(i -> (Callable<Integer>) () -> randomTask(1000, 300))
                .collect(Collectors.toList());

        try {
            allSuccessful(subtasks).stream().forEach(r -> System.out.println("Result -> " + r));
        } catch (InterruptedException e) {
            Throwable cause = e.getCause();
            System.out.println("FailedException: " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
        }
    }
}
