package org.powernukkitx.rpencrypter.utils;

import cn.nukkit.plugin.PluginLogger;
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
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

public final class ResourcePackEncrypter {
    private static final String MANIFEST_FILE = "manifest.json";
    private static final Set<String> SKIP_ENCRYPTION = new HashSet<>(Set.of(MANIFEST_FILE, "pack_icon.png"));

    private final PluginLogger logger;
    private final Gson gson = new Gson();

    public ResourcePackEncrypter(PluginLogger logger) {
        this.logger = logger;
    }

    public int encryptAllInDirectory(File directory, String encryptionKey) {
        if (!directory.isDirectory()) {
            logger.warning("resource_packs directory not found: " + directory.getAbsolutePath());
            return 0;
        }

        File[] files = directory.listFiles();
        if (files == null) {
            return 0;
        }

        int updated = 0;
        for (File file : files) {
            if (!file.isFile()) {
                continue;
            }

            String lower = file.getName().toLowerCase();
            if (!(lower.endsWith(".zip") || lower.endsWith(".mcpack"))) {
                continue;
            }
            if (new File(file.getAbsolutePath() + ".key").isFile()) {
                continue;
            }

            try {
                if (encryptPack(file, encryptionKey)) {
                    updated++;
                }
            } catch (Exception e) {
                logger.error("Failed to encrypt pack " + file.getName(), e);
            }
        }

        return updated;
    }

    private boolean encryptPack(File packFile, String encryptionKey) throws Exception {
        Path tempOutput = Files.createTempFile("rpencrypter-pnx-", ".zip");
        byte[] packKeyBytes = encryptionKey.getBytes(StandardCharsets.UTF_8);

        try (ZipFile zipFile = new ZipFile(packFile);
             ZipOutputStream output = new ZipOutputStream(Files.newOutputStream(tempOutput))) {

            List<PathKeyEntry> pathKeyList = new ArrayList<>();
            String packUuid = null;

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

                if (MANIFEST_FILE.equals(leaf)) {
                    packUuid = readPackUuid(contents);
                }

                byte[] outputBytes;
                if (SKIP_ENCRYPTION.contains(leaf)) {
                    outputBytes = contents;
                } else {
                    String fileKey = md5Hex(concat(relativePath.getBytes(StandardCharsets.UTF_8), contents));
                    byte[] fileKeyBytes = fileKey.getBytes(StandardCharsets.UTF_8);
                    outputBytes = aes256Cfb8Encrypt(contents, fileKeyBytes, slice16(fileKeyBytes));
                    pathKeyList.add(new PathKeyEntry(relativePath, fileKey));
                }

                writeZipEntry(output, relativePath, outputBytes);
            }

            if (packUuid == null || packUuid.length() != 36) {
                throw new IllegalArgumentException("manifest.json missing or invalid UUID in " + packFile.getName());
            }

            String contentsJson = gson.toJson(new ContentsJson(pathKeyList));
            byte[] encryptedContentsJson = aes256Cfb8Encrypt(
                    contentsJson.getBytes(StandardCharsets.UTF_8),
                    packKeyBytes,
                    slice16(packKeyBytes)
            );
            writeZipEntry(output, "contents.json", buildContentsFile(packUuid, encryptedContentsJson));
        }

        Files.move(tempOutput, packFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
        Files.writeString(Path.of(packFile.getAbsolutePath() + ".key"), encryptionKey, StandardCharsets.UTF_8);
        logger.info("Encrypted resource pack: " + packFile.getName());
        return true;
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
