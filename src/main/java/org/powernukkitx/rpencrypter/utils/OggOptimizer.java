package org.powernukkitx.rpencrypter.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

/**
 * Halves the sample rate of the sounds that have nothing above 11 kHz: the same sound to the ear,
 * far fewer bytes.
 *
 * Encrypted bytes no longer compress, so a sound is downloaded as heavy as it is encoded. Many sound
 * effects of a pack are synthesised low and dull, yet encoded at 44.1 kHz like music. A sound whose
 * energy above 11 kHz is under a ten-thousandth of the total is re-encoded at 22.05 kHz (Vorbis
 * quality 4, a notch above the usual one, so that the second encoding costs nothing audible).
 * Everything else is returned as is: bright sounds, long ones, loops (named so, see
 * {@link #mayResample}: resampling could leave a click where they loop), sounds already at 22 kHz,
 * anything ffmpeg can't read, and any result that isn't smaller.
 */
public final class OggOptimizer {

    private static final Pattern LOOP_NAMES = Pattern.compile(
            "loop|amb|hum|music|drone|wind|rain|storm|surf|_bg|ambience|theme", Pattern.CASE_INSENSITIVE);
    private static final double MAX_SECONDS = 10.0;
    private static final double HIGH_HZ = 11025.0;
    private static final double MAX_HIGH_RATIO = 1e-4;
    private static final int FRAME = 4096;

    private final String ffmpeg;
    private volatile boolean available = true;

    public OggOptimizer(String ffmpeg) {
        this.ffmpeg = ffmpeg;
    }

    /** Loops and long sounds are never resampled: only the file name can tell a loop. */
    public static boolean mayResample(String path) {
        String leaf = path.substring(path.lastIndexOf('/') + 1);
        return !LOOP_NAMES.matcher(leaf).find();
    }

    public boolean isAvailable() {
        return available;
    }

    /** The resampled sound, or the input itself. Never throws. */
    public byte[] optimize(byte[] ogg) {
        if (!available) return ogg;
        try {
            int[] info = vorbisInfo(ogg);
            if (info == null) return ogg;
            int channels = info[0], rate = info[1];
            if (rate <= 22050) return ogg;
            double seconds = lastGranule(ogg) / (double) rate;
            if (seconds <= 0 || seconds > MAX_SECONDS) return ogg;

            byte[] pcm = run(ogg, ffmpeg, "-v", "error", "-i", "pipe:0", "-ac", "1", "-f", "f32le", "pipe:1");
            if (pcm == null || highRatio(pcm, rate) >= MAX_HIGH_RATIO) return ogg;

            byte[] out = run(ogg, ffmpeg, "-v", "error", "-i", "pipe:0", "-map_metadata", "-1",
                    "-ac", String.valueOf(channels), "-ar", "22050", "-c:a", "libvorbis", "-q:a", "4",
                    "-fflags", "+bitexact", "-flags:a", "+bitexact", "-f", "ogg", "pipe:1");
            return out != null && out.length > 0 && out.length < ogg.length && AssetCache.isCompleteOgg(out) ? out : ogg;
        } catch (IOException e) {
            available = false; // no ffmpeg: every sound stays as it is
            return ogg;
        } catch (RuntimeException | InterruptedException e) {
            return ogg;
        }
    }

    /** Channels and sample rate, from the identification header of the first page. */
    private static int[] vorbisInfo(byte[] ogg) {
        int limit = Math.min(ogg.length - 16, 512);
        for (int i = 0; i < limit; i++) {
            if (ogg[i] == 1 && ogg[i + 1] == 'v' && ogg[i + 2] == 'o' && ogg[i + 3] == 'r' && ogg[i + 4] == 'b'
                    && ogg[i + 5] == 'i' && ogg[i + 6] == 's') {
                int channels = ogg[i + 11] & 0xFF;
                int rate = ByteBuffer.wrap(ogg, i + 12, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
                return new int[]{channels, rate};
            }
        }
        return null;
    }

    /** Samples in the stream: the granule position of its last page. */
    private static long lastGranule(byte[] ogg) {
        for (int i = ogg.length - 27; i >= 0; i--) {
            if (ogg[i] == 'O' && ogg[i + 1] == 'g' && ogg[i + 2] == 'g' && ogg[i + 3] == 'S') {
                return ByteBuffer.wrap(ogg, i + 6, 8).order(ByteOrder.LITTLE_ENDIAN).getLong();
            }
        }
        return -1;
    }

    /** Share of the energy above 11 kHz, over Hann-windowed frames. */
    static double highRatio(byte[] pcmBytes, int rate) {
        ByteBuffer buf = ByteBuffer.wrap(pcmBytes).order(ByteOrder.LITTLE_ENDIAN);
        int n = pcmBytes.length / 4;
        if (n < FRAME) return 1.0; // too short to judge: left alone
        float[] samples = new float[n];
        for (int i = 0; i < n; i++) samples[i] = buf.getFloat();
        double[] window = new double[FRAME];
        for (int i = 0; i < FRAME; i++) window[i] = 0.5 - 0.5 * Math.cos(2 * Math.PI * i / (FRAME - 1));
        int firstHigh = (int) Math.ceil(HIGH_HZ * FRAME / rate);
        double total = 0, high = 0;
        double[] re = new double[FRAME], im = new double[FRAME];
        for (int start = 0; start + FRAME <= n; start += FRAME / 2) {
            for (int i = 0; i < FRAME; i++) {
                re[i] = samples[start + i] * window[i];
                im[i] = 0;
            }
            fft(re, im);
            for (int k = 1; k <= FRAME / 2; k++) {
                double p = re[k] * re[k] + im[k] * im[k];
                total += p;
                if (k >= firstHigh) high += p;
            }
        }
        return total <= 0 ? 1.0 : high / total;
    }

    /** In-place radix-2 FFT. */
    private static void fft(double[] re, double[] im) {
        int n = re.length;
        for (int i = 1, j = 0; i < n; i++) {
            int bit = n >> 1;
            for (; (j & bit) != 0; bit >>= 1) j ^= bit;
            j ^= bit;
            if (i < j) {
                double t = re[i]; re[i] = re[j]; re[j] = t;
                t = im[i]; im[i] = im[j]; im[j] = t;
            }
        }
        for (int len = 2; len <= n; len <<= 1) {
            double angle = -2 * Math.PI / len;
            double wr = Math.cos(angle), wi = Math.sin(angle);
            for (int i = 0; i < n; i += len) {
                double cr = 1, ci = 0;
                for (int k = 0; k < len / 2; k++) {
                    int a = i + k, b = a + len / 2;
                    double xr = re[b] * cr - im[b] * ci, xi = re[b] * ci + im[b] * cr;
                    re[b] = re[a] - xr; im[b] = im[a] - xi;
                    re[a] += xr; im[a] += xi;
                    double t = cr * wr - ci * wi;
                    ci = cr * wi + ci * wr;
                    cr = t;
                }
            }
        }
    }

    /** Runs ffmpeg with the input on stdin, returns stdout, or null when it fails or takes too long. */
    private static byte[] run(byte[] input, String... command) throws IOException, InterruptedException {
        List<String> cmd = new ArrayList<>(List.of(command));
        Process process = new ProcessBuilder(cmd).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        Thread writer = new Thread(() -> {
            try (OutputStream out = process.getOutputStream()) {
                out.write(input);
            } catch (IOException ignored) {
                // ffmpeg stopped reading: its exit code tells
            }
        }, "RPEncrypter-ffmpeg-in");
        writer.setDaemon(true);
        writer.start();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (InputStream in = process.getInputStream()) {
            in.transferTo(out);
        }
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            return null;
        }
        writer.join(1000);
        return process.exitValue() == 0 ? out.toByteArray() : null;
    }
}
