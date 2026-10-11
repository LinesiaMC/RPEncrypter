package org.powernukkitx.rpencrypter.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

/**
 * Re-encodes a PNG without changing a single pixel, only fewer bytes.
 *
 * Encrypted bytes no longer compress, so a PNG is downloaded exactly as heavy as it is written.
 * Most PNGs of a pack come out of an image library with default settings: an RGBA image of a
 * dozen colours, the same filter on every row, metadata. Each image is decoded, then written
 * again in the smallest of: indexed (when it has 256 colours or less), RGB (when fully opaque)
 * or RGBA, with every row filter tried and the best deflate kept.
 *
 * Only what the game already reads in packs is written: RGBA and RGB 8 bits, indexed 8 and 4
 * bits. A source the decoder doesn't handle (grey, 16 bits, interlaced, damaged) is returned
 * as is, as is any result that isn't smaller. Colour chunks (gamma, chromaticities, sRGB, ICC
 * profile) are kept; text, dates, physical size and editor chunks are dropped.
 */
public final class PngOptimizer {

    private static final byte[] SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};
    private static final Set<String> KEPT_CHUNKS = Set.of("gAMA", "cHRM", "sRGB", "iCCP");
    private static final int ADAPTIVE = -1;

    private PngOptimizer() {}

    /** The re-encoded image, or the input itself when it can't be made smaller. */
    public static byte[] optimize(byte[] png) {
        try {
            Image image = decode(png);
            if (image == null) {
                return png;
            }
            byte[] out = encode(image);
            return out.length < png.length ? out : png;
        } catch (IOException | DataFormatException | RuntimeException e) {
            return png;
        }
    }

    private record Image(int width, int height, int[] argb, List<Chunk> kept) {}

    private record Chunk(String type, byte[] data) {}

    // ─── decoding ────────────────────────────────────────────────────────────

    static Image decode(byte[] png) throws IOException, DataFormatException {
        if (png.length < 8 || !Arrays.equals(Arrays.copyOf(png, 8), SIGNATURE)) {
            return null;
        }
        ByteBuffer buf = ByteBuffer.wrap(png, 8, png.length - 8);
        int width = 0, height = 0, depth = 0, colorType = -1;
        byte[] palette = null, transparency = null;
        ByteArrayOutputStream idat = new ByteArrayOutputStream();
        List<Chunk> kept = new ArrayList<>();
        boolean ended = false;
        while (buf.remaining() >= 12) {
            int length = buf.getInt();
            if (length < 0 || length > buf.remaining() - 8) {
                return null;
            }
            byte[] typeBytes = new byte[4];
            buf.get(typeBytes);
            byte[] data = new byte[length];
            buf.get(data);
            int crc = buf.getInt();
            if (crc != crc(typeBytes, data)) {
                return null;
            }
            String type = new String(typeBytes, StandardCharsets.US_ASCII);
            switch (type) {
                case "IHDR" -> {
                    if (length != 13) return null;
                    ByteBuffer h = ByteBuffer.wrap(data);
                    width = h.getInt();
                    height = h.getInt();
                    depth = h.get() & 0xFF;
                    colorType = h.get() & 0xFF;
                    int compression = h.get(), filter = h.get(), interlace = h.get();
                    if (compression != 0 || filter != 0 || interlace != 0) return null;
                }
                case "PLTE" -> palette = data;
                case "tRNS" -> transparency = data;
                case "IDAT" -> idat.write(data);
                case "IEND" -> ended = true;
                default -> {
                    if (KEPT_CHUNKS.contains(type)) {
                        kept.add(new Chunk(type, data));
                    } else if (Character.isUpperCase(type.charAt(0))) {
                        return null; // unknown critical chunk
                    }
                }
            }
            if (ended) break;
        }
        if (!ended || width <= 0 || height <= 0 || (long) width * height > 16_777_216L) {
            return null;
        }
        int channels;
        switch (colorType) {
            case 2 -> channels = 3;
            case 6 -> channels = 4;
            case 3 -> channels = 1;
            default -> {
                return null; // grey sources are left alone
            }
        }
        boolean indexed = colorType == 3;
        if (indexed ? !(depth == 1 || depth == 2 || depth == 4 || depth == 8) : depth != 8) {
            return null;
        }
        if (indexed && (palette == null || palette.length % 3 != 0)) {
            return null;
        }

        int bitsPerPixel = channels * depth;
        int stride = (width * bitsPerPixel + 7) / 8;
        int bpp = Math.max(1, bitsPerPixel / 8);
        byte[] raw = inflate(idat.toByteArray(), (stride + 1) * height);
        if (raw == null) {
            return null;
        }
        byte[] prev = new byte[stride];
        byte[] line = new byte[stride];
        int[] argb = new int[width * height];
        int paletteSize = indexed ? palette.length / 3 : 0;
        for (int y = 0; y < height; y++) {
            int base = y * (stride + 1);
            int filter = raw[base] & 0xFF;
            if (filter > 4) {
                return null;
            }
            System.arraycopy(raw, base + 1, line, 0, stride);
            unfilter(filter, line, prev, bpp);
            for (int x = 0; x < width; x++) {
                int a = 255, r, g, b;
                if (indexed) {
                    int index;
                    if (depth == 8) {
                        index = line[x] & 0xFF;
                    } else {
                        int bit = x * depth;
                        int shift = 8 - depth - (bit & 7);
                        index = ((line[bit >> 3] & 0xFF) >> shift) & ((1 << depth) - 1);
                    }
                    if (index >= paletteSize) return null;
                    r = palette[index * 3] & 0xFF;
                    g = palette[index * 3 + 1] & 0xFF;
                    b = palette[index * 3 + 2] & 0xFF;
                    if (transparency != null && index < transparency.length) a = transparency[index] & 0xFF;
                } else {
                    int o = x * channels;
                    r = line[o] & 0xFF;
                    g = line[o + 1] & 0xFF;
                    b = line[o + 2] & 0xFF;
                    if (channels == 4) {
                        a = line[o + 3] & 0xFF;
                    } else if (transparency != null && transparency.length == 6
                            && transparency[0] == 0 && (transparency[1] & 0xFF) == r
                            && transparency[2] == 0 && (transparency[3] & 0xFF) == g
                            && transparency[4] == 0 && (transparency[5] & 0xFF) == b) {
                        a = 0;
                    }
                }
                argb[y * width + x] = a << 24 | r << 16 | g << 8 | b;
            }
            byte[] swap = prev;
            prev = line;
            line = swap;
        }
        return new Image(width, height, argb, kept);
    }

    private static byte[] inflate(byte[] data, int expected) throws DataFormatException {
        Inflater inflater = new Inflater();
        try {
            inflater.setInput(data);
            byte[] out = new byte[expected];
            int n = 0;
            while (n < expected && !inflater.finished()) {
                int r = inflater.inflate(out, n, expected - n);
                if (r == 0 && (inflater.needsInput() || inflater.needsDictionary())) break;
                n += r;
            }
            return n == expected ? out : null;
        } finally {
            inflater.end();
        }
    }

    private static void unfilter(int filter, byte[] line, byte[] prev, int bpp) {
        for (int i = 0; i < line.length; i++) {
            int a = i >= bpp ? line[i - bpp] & 0xFF : 0;
            int b = prev[i] & 0xFF;
            int c = i >= bpp ? prev[i - bpp] & 0xFF : 0;
            int predictor = switch (filter) {
                case 1 -> a;
                case 2 -> b;
                case 3 -> (a + b) >>> 1;
                case 4 -> paeth(a, b, c);
                default -> 0;
            };
            line[i] = (byte) (line[i] + predictor);
        }
    }

    private static int paeth(int a, int b, int c) {
        int p = a + b - c;
        int pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }

    // ─── encoding ────────────────────────────────────────────────────────────

    static byte[] encode(Image image) throws IOException {
        int width = image.width(), height = image.height();
        int[] argb = image.argb();
        boolean opaque = true;
        Map<Integer, Integer> counts = new HashMap<>();
        for (int c : argb) {
            if (c >>> 24 != 255) opaque = false;
            if (counts.size() <= 256) counts.merge(c, 1, Integer::sum);
        }

        byte[] best = null;
        if (counts.size() <= 256) {
            // Translucent entries first, so tRNS stops at the last one; then the most used first.
            List<Integer> colors = new ArrayList<>(counts.keySet());
            colors.sort((x, y) -> {
                boolean tx = x >>> 24 != 255, ty = y >>> 24 != 255;
                if (tx != ty) return tx ? -1 : 1;
                int byCount = Integer.compare(counts.get(y), counts.get(x));
                return byCount != 0 ? byCount : Integer.compareUnsigned(x, y);
            });
            Map<Integer, Integer> indexOf = new HashMap<>();
            for (int i = 0; i < colors.size(); i++) indexOf.put(colors.get(i), i);
            // 2 bits would be smaller still, but no pack proves the game reads it: 4 at least.
            int depth = colors.size() <= 16 ? 4 : 8;
            int stride = (width * depth + 7) / 8;
            byte[] rows = new byte[stride * height];
            for (int y = 0; y < height; y++) {
                for (int x = 0; x < width; x++) {
                    int index = indexOf.get(argb[y * width + x]);
                    if (depth == 8) {
                        rows[y * stride + x] = (byte) index;
                    } else {
                        int bit = x * depth;
                        int shift = 8 - depth - (bit & 7);
                        rows[y * stride + (bit >> 3)] |= (byte) (index << shift);
                    }
                }
            }
            byte[] plte = new byte[colors.size() * 3];
            int translucent = 0;
            for (int i = 0; i < colors.size(); i++) {
                int c = colors.get(i);
                plte[i * 3] = (byte) (c >> 16);
                plte[i * 3 + 1] = (byte) (c >> 8);
                plte[i * 3 + 2] = (byte) c;
                if (c >>> 24 != 255) translucent = i + 1;
            }
            byte[] trns = new byte[translucent];
            for (int i = 0; i < translucent; i++) trns[i] = (byte) (colors.get(i) >>> 24);
            byte[] idat = bestStream(rows, stride, height, 1, new int[]{0, ADAPTIVE});
            best = write(image, depth, 3, plte, trns, idat);
        }

        int channels = opaque ? 3 : 4;
        int stride = width * channels;
        byte[] rows = new byte[stride * height];
        for (int i = 0, o = 0; i < argb.length; i++) {
            int c = argb[i];
            rows[o++] = (byte) (c >> 16);
            rows[o++] = (byte) (c >> 8);
            rows[o++] = (byte) c;
            if (!opaque) rows[o++] = (byte) (c >>> 24);
        }
        byte[] idat = bestStream(rows, stride, height, channels, new int[]{0, 1, 2, 3, 4, ADAPTIVE});
        byte[] truecolor = write(image, 8, opaque ? 2 : 6, null, null, idat);
        return best == null || truecolor.length < best.length ? truecolor : best;
    }

    /**
     * Filters the rows every way asked and keeps the smallest deflate. The filters are ranked with
     * a fast deflate first: the slow, thorough one only runs on the two best, which keeps a whole
     * pack to a few seconds without losing more than a few bytes.
     */
    private static byte[] bestStream(byte[] rows, int stride, int height, int bpp, int[] filters) {
        byte[][] filtered = new byte[filters.length][];
        Integer[] order = new Integer[filters.length];
        int[] quick = new int[filters.length];
        for (int i = 0; i < filters.length; i++) {
            filtered[i] = filter(rows, stride, height, bpp, filters[i]);
            quick[i] = deflate(filtered[i], Deflater.BEST_SPEED, Deflater.DEFAULT_STRATEGY).length;
            order[i] = i;
        }
        Arrays.sort(order, (x, y) -> Integer.compare(quick[x], quick[y]));
        byte[] best = null;
        for (int k = 0; k < Math.min(2, order.length); k++) {
            for (int strategy : new int[]{Deflater.DEFAULT_STRATEGY, Deflater.FILTERED}) {
                byte[] compressed = deflate(filtered[order[k]], Deflater.BEST_COMPRESSION, strategy);
                if (best == null || compressed.length < best.length) best = compressed;
            }
        }
        return best;
    }

    private static byte[] filter(byte[] rows, int stride, int height, int bpp, int filter) {
        byte[] out = new byte[(stride + 1) * height];
        byte[] candidate = new byte[stride];
        byte[] chosen = new byte[stride];
        byte[] zero = new byte[stride];
        for (int y = 0; y < height; y++) {
            int base = y * stride;
            byte[] prev = y == 0 ? zero : Arrays.copyOfRange(rows, base - stride, base);
            byte[] line = Arrays.copyOfRange(rows, base, base + stride);
            int type = filter;
            if (filter == ADAPTIVE) {
                long bestSum = Long.MAX_VALUE;
                for (int t = 0; t < 5; t++) {
                    applyFilter(t, line, prev, bpp, candidate);
                    long sum = 0;
                    for (byte v : candidate) sum += Math.abs((int) v);
                    if (sum < bestSum) {
                        bestSum = sum;
                        type = t;
                        System.arraycopy(candidate, 0, chosen, 0, stride);
                    }
                }
            } else {
                applyFilter(type, line, prev, bpp, chosen);
            }
            out[y * (stride + 1)] = (byte) type;
            System.arraycopy(chosen, 0, out, y * (stride + 1) + 1, stride);
        }
        return out;
    }

    private static void applyFilter(int type, byte[] line, byte[] prev, int bpp, byte[] out) {
        for (int i = 0; i < line.length; i++) {
            int a = i >= bpp ? line[i - bpp] & 0xFF : 0;
            int b = prev[i] & 0xFF;
            int c = i >= bpp ? prev[i - bpp] & 0xFF : 0;
            int predictor = switch (type) {
                case 1 -> a;
                case 2 -> b;
                case 3 -> (a + b) >>> 1;
                case 4 -> paeth(a, b, c);
                default -> 0;
            };
            out[i] = (byte) ((line[i] & 0xFF) - predictor);
        }
    }

    private static byte[] deflate(byte[] data, int level, int strategy) {
        Deflater deflater = new Deflater(level);
        try {
            deflater.setStrategy(strategy);
            deflater.setInput(data);
            deflater.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(Math.max(64, data.length / 4));
            byte[] chunk = new byte[65536];
            while (!deflater.finished()) {
                int n = deflater.deflate(chunk);
                out.write(chunk, 0, n);
            }
            return out.toByteArray();
        } finally {
            deflater.end();
        }
    }

    private static byte[] write(Image image, int depth, int colorType, byte[] plte, byte[] trns, byte[] idat)
            throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(idat.length + 128);
        out.write(SIGNATURE);
        ByteBuffer ihdr = ByteBuffer.allocate(13);
        ihdr.putInt(image.width()).putInt(image.height())
            .put((byte) depth).put((byte) colorType).put((byte) 0).put((byte) 0).put((byte) 0);
        writeChunk(out, "IHDR", ihdr.array());
        for (Chunk chunk : image.kept()) {
            writeChunk(out, chunk.type(), chunk.data());
        }
        if (plte != null) writeChunk(out, "PLTE", plte);
        if (trns != null && trns.length > 0) writeChunk(out, "tRNS", trns);
        writeChunk(out, "IDAT", idat);
        writeChunk(out, "IEND", new byte[0]);
        return out.toByteArray();
    }

    private static void writeChunk(ByteArrayOutputStream out, String type, byte[] data) throws IOException {
        byte[] typeBytes = type.getBytes(StandardCharsets.US_ASCII);
        out.write(ByteBuffer.allocate(4).putInt(data.length).array());
        out.write(typeBytes);
        out.write(data);
        out.write(ByteBuffer.allocate(4).putInt(crc(typeBytes, data)).array());
    }

    private static int crc(byte[] type, byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(type);
        crc.update(data);
        return (int) crc.getValue();
    }
}
