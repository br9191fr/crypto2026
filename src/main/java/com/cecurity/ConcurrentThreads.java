package com.cecurity;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

public class ConcurrentThreads {
    private static final List<String> sharedList = new ArrayList<>();
    public static void main(String[] args) {

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
        System.out.println("Final list: " + sharedList);
    }
    private static synchronized void addItem(String value) {
        sharedList.add(value);
    }
}
