package org.powernukkitx.rpencrypter.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runs {@link PngOptimizer} on a few threads and remembers every result by the hash of its source.
 *
 * Packs are re-encrypted at every startup: only the images that changed since the last one are
 * re-encoded, the others come back from the cache in no time. Results nobody asked for during a
 * run (images removed from the packs) are deleted by {@link #prune()}.
 */
public final class PngCache implements AutoCloseable {

    private final File dir;
    private final ExecutorService pool;
    private final Set<String> used = ConcurrentHashMap.newKeySet();
    private final AtomicLong bytesBefore = new AtomicLong();
    private final AtomicLong bytesAfter = new AtomicLong();
    private final AtomicInteger encoded = new AtomicInteger();
    private final AtomicInteger cached = new AtomicInteger();

    public PngCache(File dir, int threads) {
        this.dir = dir;
        this.pool = Executors.newFixedThreadPool(Math.max(1, threads), runnable -> {
            Thread thread = new Thread(runnable, "RPEncrypter-png");
            thread.setDaemon(true);
            thread.setPriority(Thread.MIN_PRIORITY);
            return thread;
        });
        dir.mkdirs();
    }

    /** The bytes to ship for this image, once ready. */
    public Future<byte[]> submit(byte[] png) {
        return pool.submit(() -> get(png));
    }

    /** Never fails: a cache that can't be read or written only costs the time to re-encode. */
    private byte[] get(byte[] png) {
        String key = sha1(png);
        used.add(key);
        File file = new File(dir, key + ".png");
        byte[] out = null;
        try {
            if (file.isFile()) {
                byte[] stored = Files.readAllBytes(file.toPath());
                if (stored.length <= png.length && isComplete(stored)) {
                    out = stored;
                    cached.incrementAndGet();
                }
            }
        } catch (IOException ignored) {
            // re-encoded below
        }
        if (out == null) {
            out = PngOptimizer.optimize(png);
            encoded.incrementAndGet();
            // Its own temporary file: the same image can sit in several packs and be re-encoded twice at once.
            Path temp = null;
            try {
                temp = Files.createTempFile(dir.toPath(), key, ".tmp");
                Files.write(temp, out);
                Files.move(temp, file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException e) {
                if (temp != null) temp.toFile().delete();
            }
        }
        bytesBefore.addAndGet(png.length);
        bytesAfter.addAndGet(out.length);
        return out;
    }

    /** A whole PNG: the signature at the start, the IEND chunk at the end. */
    private static boolean isComplete(byte[] png) {
        int n = png.length;
        return n > 20 && png[1] == 'P' && png[2] == 'N' && png[3] == 'G'
                && png[n - 8] == 'I' && png[n - 7] == 'E' && png[n - 6] == 'N' && png[n - 5] == 'D';
    }

    /** Deletes the results of images that are no longer in any pack. */
    public void prune() {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            String name = file.getName();
            if (name.endsWith(".tmp") || (name.endsWith(".png") && !used.contains(name.substring(0, name.length() - 4)))) {
                file.delete();
            }
        }
    }

    public String summary() {
        return String.format(Locale.ROOT, "PNG re-encoded without loss: %.1f MB -> %.1f MB (%d re-encoded, %d from cache)",
                bytesBefore.get() / 1e6, bytesAfter.get() / 1e6, encoded.get(), cached.get());
    }

    public boolean isEmpty() {
        return bytesBefore.get() == 0;
    }

    @Override
    public void close() {
        pool.shutdownNow();
    }

    private static String sha1(byte[] data) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-1").digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 algorithm is unavailable", e);
        }
    }
}
