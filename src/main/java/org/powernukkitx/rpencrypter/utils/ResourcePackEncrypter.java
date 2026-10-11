package org.powernukkitx.rpencrypter.utils;

import org.powernukkitx.plugin.PluginLogger;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class ResourcePackEncrypter {
    private static final String MANIFEST_FILE = "manifest.json";
    private static final Set<String> SKIP_ENCRYPTION = new HashSet<>(Set.of(MANIFEST_FILE, "pack_icon.png"));
    private static final LocalDateTime FIXED_ENTRY_TIME = LocalDateTime.of(2000, 1, 1, 0, 0, 0);

    private final PluginLogger logger;
    private final Gson gson = new Gson();
    private long jsonBytesBefore;
    private long jsonBytesAfter;

    public ResourcePackEncrypter(PluginLogger logger) {
        this.logger = logger;
    }

    /**
     * Encrypted bytes no longer compress: every file of an encrypted pack is downloaded exactly as
     * heavy as it is written. Both options make the files lighter before they are encrypted.
     *
     * @param minifyJson strip indentation and comments from the JSON files
     * @param pngCache   re-encodes the PNGs without loss, or {@code null} to keep them as they are
     */
    public int encryptAll(List<File> packs, File outputDirectory, String encryptionKey,
                          Set<String> excludedPacks, boolean minifyJson, PngCache pngCache) {
        if (!outputDirectory.exists()) {
            outputDirectory.mkdirs();
        }

        int updated = 0;
        jsonBytesBefore = 0;
        jsonBytesAfter = 0;
        for (File file : packs) {
            if (!file.isFile()) {
                continue;
            }

            String lower = file.getName().toLowerCase(Locale.ROOT);
            if (!(lower.endsWith(".zip") || lower.endsWith(".mcpack"))) {
                continue;
            }
            if (excludedPacks.contains(stripExtension(lower))) {
                logger.info("Pack excluded from encryption: " + file.getName());
                continue;
            }
            File outputFile = new File(outputDirectory, file.getName());

            try {
                if (encryptPack(file, outputFile, encryptionKey, minifyJson, pngCache)) {
                    updated++;
                }
            } catch (Exception e) {
                logger.error("Failed to encrypt pack " + file.getName(), e);
            }
        }

        if (minifyJson && jsonBytesBefore > 0) {
            logger.info(String.format(Locale.ROOT, "JSON minified before encryption: %.1f MB -> %.1f MB",
                    jsonBytesBefore / 1e6, jsonBytesAfter / 1e6));
        }
        if (pngCache != null && !pngCache.isEmpty()) {
            logger.info(pngCache.summary());
        }
        return updated;
    }

    private static String stripExtension(String lowerCaseName) {
        int dot = lowerCaseName.lastIndexOf('.');
        return dot < 0 ? lowerCaseName : lowerCaseName.substring(0, dot);
    }

    private record PackFile(String path, String leaf, byte[] contents, Future<byte[]> png) {}

    private boolean encryptPack(File packFile, File outputFile, String encryptionKey, boolean minifyJson,
                                PngCache pngCache) throws Exception {
        Path tempOutput = Files.createTempFile("rpencrypter-pnx-", ".zip");
        try {
            byte[] packKeyBytes = encryptionKey.getBytes(StandardCharsets.UTF_8);

            // Read first, so that the images are re-encoded on several threads while the rest waits.
            List<PackFile> files = new ArrayList<>();
            String packUuid = null;
            try (ZipFile zipFile = new ZipFile(packFile)) {
                var entries = zipFile.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    if (entry.isDirectory()) {
                        continue;
                    }

                    String relativePath = entry.getName();
                    byte[] contents;
                    try (var input = zipFile.getInputStream(entry)) {
                        contents = input.readAllBytes();
                    }
                    String leaf = Path.of(relativePath).getFileName().toString();
                    String lowerLeaf = leaf.toLowerCase(Locale.ROOT);

                    Future<byte[]> png = null;
                    if (MANIFEST_FILE.equals(leaf)) {
                        packUuid = readPackUuid(contents);
                    } else if (minifyJson && lowerLeaf.endsWith(".json")) {
                        jsonBytesBefore += contents.length;
                        contents = JsonMinifier.minify(contents);
                        jsonBytesAfter += contents.length;
                    } else if (pngCache != null && lowerLeaf.endsWith(".png")) {
                        png = pngCache.submit(contents);
                    }
                    files.add(new PackFile(relativePath, leaf, contents, png));
                }
            }

            if (packUuid == null || packUuid.length() != 36) {
                throw new IllegalArgumentException("manifest.json missing or invalid UUID in " + packFile.getName());
            }

            try (ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(tempOutput))) {
                List<PathKeyEntry> pathKeyList = new ArrayList<>();
                for (PackFile file : files) {
                    byte[] contents = file.contents();
                    if (file.png() != null) {
                        try {
                            contents = file.png().get();
                        } catch (ExecutionException e) {
                            logger.warning("PNG kept as is, re-encoding failed: " + file.path());
                        }
                    }

                    byte[] outputBytes;
                    if (SKIP_ENCRYPTION.contains(file.leaf())) {
                        outputBytes = contents;
                    } else {
                        String fileKey = md5Hex(concat(file.path().getBytes(StandardCharsets.UTF_8), contents));
                        byte[] fileKeyBytes = fileKey.getBytes(StandardCharsets.UTF_8);
                        outputBytes = aes256Cfb8Encrypt(contents, fileKeyBytes, slice16(fileKeyBytes));
                        pathKeyList.add(new PathKeyEntry(file.path(), fileKey));
                    }

                    writeZipEntry(output, file.path(), outputBytes);
                }

                String contentsJson = gson.toJson(new ContentsJson(pathKeyList));
                byte[] encryptedContentsJson = aes256Cfb8Encrypt(
                        contentsJson.getBytes(StandardCharsets.UTF_8),
                        packKeyBytes,
                        slice16(packKeyBytes)
                );
                writeZipEntry(output, "contents.json", buildContentsFile(packUuid, encryptedContentsJson));
            }

            Files.move(tempOutput, outputFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            Files.writeString(Path.of(outputFile.getAbsolutePath() + ".key"), encryptionKey, StandardCharsets.UTF_8);
            return true;
        } finally {
            Files.deleteIfExists(tempOutput);
        }
    }

    private static String readPackUuid(byte[] manifestBytes) {
        JsonObject root = JsonParser.parseString(new String(manifestBytes, StandardCharsets.UTF_8)).getAsJsonObject();
        return root.getAsJsonObject("header").get("uuid").getAsString();
    }

    private static byte[] aes256Cfb8Encrypt(byte[] plaintext, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(plaintext);
    }

    private static byte[] buildContentsFile(String packUuid, byte[] encryptedJson) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(new byte[]{0, 0, 0, 0});
        out.write(new byte[]{(byte) 0xFC, (byte) 0xB9, (byte) 0xCF, (byte) 0x9B});
        out.write(new byte[]{0, 0, 0, 0, 0, 0, 0, 0});
        out.write(0x24);
        out.write(packUuid.getBytes(StandardCharsets.UTF_8));

        int current = out.size();
        if (current < 256) {
            out.write(new byte[256 - current]);
        }

        out.write(encryptedJson);
        return out.toByteArray();
    }

    private static void writeZipEntry(ZipOutputStream output, String path, byte[] data) throws IOException {
        ZipEntry outEntry = new ZipEntry(path);
        // Packs are re-encrypted at every startup: a fixed entry date keeps the output byte-identical,
        // so the SHA-256 doesn't move and clients don't re-download the whole pack after each restart.
        outEntry.setTimeLocal(FIXED_ENTRY_TIME);
        // Stored, not deflated: encrypted bytes don't compress, deflating them only adds a few bytes
        // per file (and a data descriptor), over thousands of files.
        CRC32 crc = new CRC32();
        crc.update(data);
        outEntry.setMethod(ZipEntry.STORED);
        outEntry.setSize(data.length);
        outEntry.setCompressedSize(data.length);
        outEntry.setCrc(crc.getValue());
        output.putNextEntry(outEntry);
        output.write(data);
        output.closeEntry();
    }

    private static byte[] slice16(byte[] source) {
        byte[] result = new byte[16];
        System.arraycopy(source, 0, result, 0, 16);
        return result;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }

    private static String md5Hex(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            byte[] hash = digest.digest(input);
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("MD5 algorithm is unavailable", e);
        }
    }

    private record PathKeyEntry(String path, String key) {}

    private record ContentsJson(List<PathKeyEntry> content) {}
}
