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
import java.util.function.Predicate;
import java.util.function.UnaryOperator;

/**
 * Runs an optimizer (images, sounds) on a few threads and remembers every result by the hash of its source.
 *
 * Packs are re-encrypted at every startup: only the files that changed since the last one are
 * re-encoded, the others come back from the cache in no time. Results nobody asked for during a
 * run (files removed from the packs) are deleted by {@link #prune()}.
 */
public final class AssetCache implements AutoCloseable {

    private final File dir;
    private final String label;
    private final String extension;
    private final UnaryOperator<byte[]> optimizer;
    private final Predicate<byte[]> complete;
    private final ExecutorService pool;
    private final Set<String> used = ConcurrentHashMap.newKeySet();
    private final AtomicLong bytesBefore = new AtomicLong();
    private final AtomicLong bytesAfter = new AtomicLong();
    private final AtomicInteger encoded = new AtomicInteger();
    private final AtomicInteger cached = new AtomicInteger();

    /**
     * @param label     what the summary calls these files ("PNG", "OGG")
     * @param extension the extension of the cached results
     * @param optimizer returns the smaller version of a file, or the file itself; never throws
     * @param complete  tells a whole cached result from a truncated one
     */
    public AssetCache(File dir, int threads, String label, String extension,
                      UnaryOperator<byte[]> optimizer, Predicate<byte[]> complete) {
        this.dir = dir;
        this.label = label;
        this.extension = extension;
        this.optimizer = optimizer;
        this.complete = complete;
        this.pool = Executors.newFixedThreadPool(Math.max(1, threads), runnable -> {
            Thread thread = new Thread(runnable, "RPEncrypter-" + label.toLowerCase(Locale.ROOT));
            thread.setDaemon(true);
            thread.setPriority(Thread.MIN_PRIORITY);
            return thread;
        });
        dir.mkdirs();
    }

    /** The bytes to ship for this file, once ready. */
    public Future<byte[]> submit(byte[] source) {
        return pool.submit(() -> get(source));
    }

    /** Never fails: a cache that can't be read or written only costs the time to re-encode. */
    private byte[] get(byte[] source) {
        String key = sha1(source);
        used.add(key);
        File file = new File(dir, key + extension);
        byte[] out = null;
        try {
            if (file.isFile()) {
                byte[] stored = Files.readAllBytes(file.toPath());
                if (stored.length > 0 && stored.length <= source.length && complete.test(stored)) {
                    out = stored;
                    cached.incrementAndGet();
                }
            }
        } catch (IOException ignored) {
            // re-encoded below
        }
        if (out == null) {
            out = optimizer.apply(source);
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
        bytesBefore.addAndGet(source.length);
        bytesAfter.addAndGet(out.length);
        return out;
    }

    /** A whole PNG: the signature at the start, the IEND chunk at the end. */
    public static boolean isCompletePng(byte[] png) {
        int n = png.length;
        return n > 20 && png[1] == 'P' && png[2] == 'N' && png[3] == 'G'
                && png[n - 8] == 'I' && png[n - 7] == 'E' && png[n - 6] == 'N' && png[n - 5] == 'D';
    }

    /** A whole Ogg stream: a page at the start, the last page flagged as the end of the stream. */
    public static boolean isCompleteOgg(byte[] ogg) {
        if (ogg.length < 28 || ogg[0] != 'O' || ogg[1] != 'g' || ogg[2] != 'g' || ogg[3] != 'S') return false;
        for (int i = ogg.length - 27; i >= 0; i--) {
            if (ogg[i] == 'O' && ogg[i + 1] == 'g' && ogg[i + 2] == 'g' && ogg[i + 3] == 'S') {
                return (ogg[i + 5] & 0x04) != 0;
            }
        }
        return false;
    }

    /** Deletes the results of files that are no longer in any pack. */
    public void prune() {
        File[] files = dir.listFiles();
        if (files == null) return;
        for (File file : files) {
            String name = file.getName();
            if (name.endsWith(".tmp") || (name.endsWith(extension) && !used.contains(name.substring(0, name.length() - extension.length())))) {
                file.delete();
            }
        }
    }

    public String summary() {
        return String.format(Locale.ROOT, "%s re-encoded: %.1f MB -> %.1f MB (%d re-encoded, %d from cache)",
                label, bytesBefore.get() / 1e6, bytesAfter.get() / 1e6, encoded.get(), cached.get());
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
