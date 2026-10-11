package org.powernukkitx.rpencrypter.utils;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.gson.Strictness;
import com.google.gson.stream.JsonReader;
import org.powernukkitx.plugin.PluginLogger;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;

/**
 * Builds one resource pack out of several: the client downloads and loads one pack instead of many.
 *
 * Files are copied as they are. When two packs have the same path:
 * <ul>
 *   <li>registry files that the game itself adds up across packs (texts, sound definitions,
 *       item and terrain textures, blocks.json, sounds.json, flipbooks, ui_defs, languages) are
 *       merged: objects key by key, arrays one after the other, .lang files line by line;</li>
 *   <li>definition files, which the game knows by the identifier inside them and not by their path
 *       (particles, fogs, entities, models, animations, render controllers, attachables), are all
 *       kept, the later ones renamed;</li>
 *   <li>anything else keeps the first pack's file, with a warning.</li>
 * </ul>
 * The merged pack gets a fixed identity (from its name) and a version taken from its content:
 * it changes as soon as one of its packs does, and only then.
 */
public final class PackMerger {

    private static final List<String> DEFINITION_DIRS = List.of("particles/", "fogs/", "entity/", "models/",
            "animations/", "animation_controllers/", "render_controllers/", "attachables/");
    private static final Set<String> PACK_TEXT_KEYS = Set.of("pack.name", "pack.description");
    private static final LocalDateTime FIXED_ENTRY_TIME = LocalDateTime.of(2000, 1, 1, 0, 0, 0);
    private static final Gson GSON = new Gson();

    /** What a merge produced: the pack file and the packs it stands for. */
    public record Result(File file, UUID uuid, Set<UUID> sources, String version) {}

    private final PluginLogger logger;
    private int conflicts;

    public PackMerger(PluginLogger logger) {
        this.logger = logger;
    }

    public Result merge(String name, List<File> sources, File outputFile) throws IOException {
        Map<String, byte[]> files = new TreeMap<>();
        Map<String, JsonElement> merged = new TreeMap<>();
        Map<String, String> owner = new TreeMap<>();
        Set<UUID> sourceIds = new LinkedHashSet<>();
        List<String> described = new ArrayList<>();
        int[] minEngine = {1, 16, 0};
        conflicts = 0;

        for (File source : sources) {
            String pack = stripExtension(source.getName());
            try (ZipFile zip = new ZipFile(source)) {
                ZipEntry manifestEntry = zip.getEntry("manifest.json");
                if (manifestEntry == null) {
                    throw new IOException("manifest.json missing in " + source.getName());
                }
                JsonObject header = parse(zip.getInputStream(manifestEntry).readAllBytes()).getAsJsonObject()
                        .getAsJsonObject("header");
                sourceIds.add(UUID.fromString(header.get("uuid").getAsString()));
                described.add(pack + " " + versionString(header.getAsJsonArray("version")));
                if (header.has("min_engine_version")) {
                    int[] v = toInts(header.getAsJsonArray("min_engine_version"));
                    if (compare(v, minEngine) > 0) minEngine = v;
                }

                var entries = zip.entries();
                while (entries.hasMoreElements()) {
                    ZipEntry entry = entries.nextElement();
                    String path = entry.getName();
                    if (entry.isDirectory() || path.equals("manifest.json") || isHidden(path)) {
                        continue;
                    }
                    byte[] data = zip.getInputStream(entry).readAllBytes();
                    add(files, merged, owner, pack, path, data);
                }
            }
        }

        for (Map.Entry<String, JsonElement> entry : merged.entrySet()) {
            files.put(entry.getKey(), GSON.toJson(entry.getValue()).getBytes(StandardCharsets.UTF_8));
        }
        for (Map.Entry<String, byte[]> entry : files.entrySet()) {
            if (entry.getKey().endsWith(".lang")) {
                entry.setValue(withoutPackTexts(entry.getValue()));
            }
        }

        UUID uuid = UUID.nameUUIDFromBytes(("rpencrypter:merged:" + name).getBytes(StandardCharsets.UTF_8));
        UUID module = UUID.nameUUIDFromBytes(("rpencrypter:merged:" + name + ":resources").getBytes(StandardCharsets.UTF_8));
        int[] version = contentVersion(files);
        JsonObject manifest = new JsonObject();
        manifest.addProperty("format_version", 2);
        JsonObject header = new JsonObject();
        header.addProperty("name", name);
        header.addProperty("description", String.join(", ", described));
        header.addProperty("uuid", uuid.toString());
        header.add("version", toArray(version));
        header.add("min_engine_version", toArray(minEngine));
        manifest.add("header", header);
        JsonArray modules = new JsonArray();
        JsonObject resources = new JsonObject();
        resources.addProperty("type", "resources");
        resources.addProperty("uuid", module.toString());
        resources.add("version", toArray(version));
        modules.add(resources);
        manifest.add("modules", modules);
        files.put("manifest.json", GSON.toJson(manifest).getBytes(StandardCharsets.UTF_8));

        writeZip(files, outputFile);
        String versionText = version[0] + "." + version[1] + "." + version[2];
        logger.info("Packs merged into " + name + " " + versionText + ": " + String.join(", ", described)
                + (conflicts > 0 ? " (" + conflicts + " conflict(s), first pack kept)" : ""));
        return new Result(outputFile, uuid, sourceIds, versionText);
    }

    private void add(Map<String, byte[]> files, Map<String, JsonElement> merged, Map<String, String> owner,
                     String pack, String path, byte[] data) {
        if (!files.containsKey(path) && !merged.containsKey(path)) {
            files.put(path, data);
            owner.put(path, pack);
            return;
        }
        byte[] existing = files.get(path);
        if (existing != null && java.util.Arrays.equals(existing, data)) {
            return;
        }
        if (path.equals("pack_icon.png")) {
            return;
        }
        if (path.endsWith(".lang")) {
            files.put(path, concatLines(existing, data));
            return;
        }
        if (isDefinition(path)) {
            String renamed = renamed(path, pack, files);
            files.put(renamed, data);
            owner.put(renamed, pack);
            return;
        }
        if (path.endsWith(".json")) {
            try {
                JsonElement base = merged.containsKey(path) ? merged.get(path) : parse(existing);
                JsonElement next = parse(data);
                merged.put(path, deepMerge(base, next, path, pack));
                files.remove(path);
                return;
            } catch (RuntimeException e) {
                // falls through to a plain conflict
            }
        }
        conflicts++;
        logger.warning("Merge conflict on " + path + ": " + owner.get(path) + " kept, " + pack + " ignored");
    }

    /** Objects key by key, arrays one after the other (without repeats), the first value otherwise. */
    private JsonElement deepMerge(JsonElement base, JsonElement next, String path, String pack) {
        if (isFormatKey(path)) {
            return base; // a version written as an array must not be added up like a list
        }
        if (base.isJsonObject() && next.isJsonObject()) {
            JsonObject out = base.getAsJsonObject().deepCopy();
            for (Map.Entry<String, JsonElement> entry : next.getAsJsonObject().entrySet()) {
                String key = entry.getKey();
                if (!out.has(key)) {
                    out.add(key, entry.getValue());
                } else {
                    out.add(key, deepMerge(out.get(key), entry.getValue(), path + " > " + key, pack));
                }
            }
            return out;
        }
        if (base.isJsonArray() && next.isJsonArray()) {
            JsonArray out = base.getAsJsonArray().deepCopy();
            for (JsonElement element : next.getAsJsonArray()) {
                if (!out.contains(element)) out.add(element);
            }
            return out;
        }
        if (!base.equals(next)) {
            conflicts++;
            logger.warning("Merge conflict on " + path + ": first value kept, " + pack + " ignored");
        }
        return base;
    }

    private static boolean isFormatKey(String path) {
        return path.endsWith("format_version") || path.endsWith("resource_pack_name")
                || path.endsWith("texture_name") || path.endsWith("num_mip_levels") || path.endsWith("padding");
    }

    private static boolean isDefinition(String path) {
        if (!path.endsWith(".json")) return false;
        for (String dir : DEFINITION_DIRS) {
            if (path.startsWith(dir)) return true;
        }
        return false;
    }

    private static String renamed(String path, String pack, Map<String, byte[]> files) {
        int dot = path.lastIndexOf('.');
        String base = path.substring(0, dot) + "__" + pack;
        String candidate = base + path.substring(dot);
        for (int i = 2; files.containsKey(candidate); i++) {
            candidate = base + i + path.substring(dot);
        }
        return candidate;
    }

    private static boolean isHidden(String path) {
        for (String part : path.split("/")) {
            if (part.startsWith(".")) return true;
        }
        return false;
    }

    private static byte[] concatLines(byte[] first, byte[] second) {
        String a = new String(first, StandardCharsets.UTF_8);
        String b = new String(second, StandardCharsets.UTF_8);
        if (b.startsWith("﻿")) b = b.substring(1);
        if (!a.isEmpty() && !a.endsWith("\n")) a += "\n";
        return (a + b).getBytes(StandardCharsets.UTF_8);
    }

    /** The name and description of each source pack mean nothing in the merged one. */
    private static byte[] withoutPackTexts(byte[] lang) {
        String text = new String(lang, StandardCharsets.UTF_8);
        StringBuilder out = new StringBuilder(text.length());
        for (String line : text.split("\n", -1)) {
            String key = line.replace("﻿", "").trim();
            int eq = key.indexOf('=');
            if (eq > 0 && PACK_TEXT_KEYS.contains(key.substring(0, eq).trim())) continue;
            out.append(line).append('\n');
        }
        if (out.length() > 0) out.setLength(out.length() - 1);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static JsonElement parse(byte[] data) {
        String text = new String(data, StandardCharsets.UTF_8);
        if (text.startsWith("﻿")) text = text.substring(1);
        JsonReader reader = new JsonReader(new StringReader(text));
        reader.setStrictness(Strictness.LENIENT);
        return JsonParser.parseReader(reader);
    }

    /** Version from the content: a new one as soon as one byte changes, the same one otherwise. */
    private static int[] contentVersion(Map<String, byte[]> files) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (Map.Entry<String, byte[]> entry : files.entrySet()) {
                digest.update(entry.getKey().getBytes(StandardCharsets.UTF_8));
                digest.update((byte) 0);
                digest.update(ByteBuffer.allocate(4).putInt(entry.getValue().length).array());
                digest.update(entry.getValue());
            }
            long h = ByteBuffer.wrap(digest.digest()).getLong() & Long.MAX_VALUE;
            return new int[]{1, (int) (h % 10_000), (int) ((h / 10_000) % 10_000)};
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm is unavailable", e);
        }
    }

    private static void writeZip(Map<String, byte[]> files, File outputFile) throws IOException {
        outputFile.getParentFile().mkdirs();
        File temp = new File(outputFile.getParentFile(), outputFile.getName() + ".tmp");
        try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(temp.toPath()))) {
            for (Map.Entry<String, byte[]> entry : files.entrySet()) {
                ZipEntry zipEntry = new ZipEntry(entry.getKey());
                zipEntry.setTimeLocal(FIXED_ENTRY_TIME);
                out.putNextEntry(zipEntry);
                out.write(entry.getValue());
                out.closeEntry();
            }
        }
        Files.move(temp.toPath(), outputFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    }

    private static String stripExtension(String name) {
        int dot = name.lastIndexOf('.');
        return dot < 0 ? name : name.substring(0, dot);
    }

    private static String versionString(JsonArray version) {
        List<String> parts = new ArrayList<>();
        for (JsonElement element : version) parts.add(element.getAsString());
        return String.join(".", parts);
    }

    private static int[] toInts(JsonArray array) {
        int[] out = new int[array.size()];
        for (int i = 0; i < out.length; i++) out[i] = array.get(i).getAsInt();
        return out;
    }

    private static int compare(int[] a, int[] b) {
        for (int i = 0; i < Math.max(a.length, b.length); i++) {
            int x = i < a.length ? a[i] : 0, y = i < b.length ? b[i] : 0;
            if (x != y) return Integer.compare(x, y);
        }
        return 0;
    }

    private static JsonArray toArray(int[] values) {
        JsonArray array = new JsonArray();
        for (int v : values) array.add(new JsonPrimitive(v));
        return array;
    }
}
