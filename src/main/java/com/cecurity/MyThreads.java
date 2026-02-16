package com.cecurity;

public class MyThreads {
    static void main() {
        new Thread(new Runnable() {
            public void run() {
                System.out.println("Hello from a thread!");
            }
        }).start();
        Runnable task = () -> {
            System.out.println("Running in: " + Thread.currentThread());
        };
        try {
            Thread vt1 = Thread.ofVirtual().unstarted(task);
            Thread vt2 = Thread.ofVirtual().unstarted(task);

            vt1.start();
            vt2.start();

            vt1.join();
            vt2.join();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
