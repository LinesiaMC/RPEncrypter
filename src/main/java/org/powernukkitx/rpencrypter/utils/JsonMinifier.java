package org.powernukkitx.rpencrypter.utils;

import java.io.ByteArrayOutputStream;

/**
 * Strips indentation, line breaks and comments from a JSON file without parsing it.
 *
 * Encrypted bytes no longer compress: once a pack is encrypted, every indentation byte of its
 * JSON files goes over the wire, and they are most of a pack's weight. Nothing is rewritten:
 * strings, numbers, key order and duplicate keys come out exactly as written. A blank or a
 * comment between two values that are not separated by a bracket, a comma or a colon is turned
 * into one space, so even a file that only a lenient reader accepts keeps its meaning.
 */
public final class JsonMinifier {

    private JsonMinifier() {}

    /** The minified bytes, or the input itself when nothing can be saved. */
    public static byte[] minify(byte[] in) {
        int n = in.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream(n);
        int i = 0;
        // UTF-8 byte order mark: the game reads the file as UTF-8 either way.
        if (n >= 3 && (in[0] & 0xFF) == 0xEF && (in[1] & 0xFF) == 0xBB && (in[2] & 0xFF) == 0xBF) {
            i = 3;
        }
        int last = -1;
        boolean gap = false;
        while (i < n) {
            int b = in[i] & 0xFF;
            if (b == ' ' || b == '\t' || b == '\n' || b == '\r') {
                gap = true;
                i++;
                continue;
            }
            if (b == '/' && i + 1 < n && in[i + 1] == '/') {
                i += 2;
                while (i < n && in[i] != '\n') i++;
                gap = true;
                continue;
            }
            if (b == '/' && i + 1 < n && in[i + 1] == '*') {
                i += 2;
                while (i < n && !(in[i] == '*' && i + 1 < n && in[i + 1] == '/')) i++;
                i = Math.min(n, i + 2);
                gap = true;
                continue;
            }
            if (gap && last >= 0 && !isStructural(last) && !isStructural(b)) {
                out.write(' ');
            }
            gap = false;
            if (b == '"') {
                // Copied as is up to the closing quote; multi-byte UTF-8 never contains an ASCII byte.
                int start = i++;
                while (i < n) {
                    byte c = in[i++];
                    if (c == '\\') {
                        i++;
                    } else if (c == '"') {
                        break;
                    }
                }
                i = Math.min(n, i);
                out.write(in, start, i - start);
                last = '"';
                continue;
            }
            out.write(b);
            last = b;
            i++;
        }
        return out.size() < n ? out.toByteArray() : in;
    }

    private static boolean isStructural(int b) {
        return b == '{' || b == '}' || b == '[' || b == ']' || b == ',' || b == ':';
    }
}
