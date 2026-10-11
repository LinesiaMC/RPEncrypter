package org.powernukkitx.rpencrypter;

import org.powernukkitx.PowerNukkitX;
import org.powernukkitx.plugin.PluginBase;
import org.powernukkitx.utils.Config;
import org.powernukkitx.utils.ConfigSection;
import org.powernukkitx.rpencrypter.utils.AssetCache;
import org.powernukkitx.rpencrypter.utils.OggOptimizer;
import org.powernukkitx.rpencrypter.utils.PackMerger;
import org.powernukkitx.rpencrypter.utils.PngOptimizer;
import org.powernukkitx.rpencrypter.utils.ResourcePackEncrypter;

import org.powernukkitx.resourcepacks.ResourcePack;
import org.powernukkitx.resourcepacks.ResourcePackManager;
import org.powernukkitx.resourcepacks.ZippedResourcePack;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class RPEncrypterPlugin extends PluginBase {
    private static final String KEY_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[]{}()!?@#$%^&*+-_=.:,;";
    private static final String EXCLUDED_PACKS_KEY = "excluded-packs";
    private static final String MERGED_PACKS_KEY = "merged-packs";

    private ResourcePackEncrypter encrypter;
    private String encryptionKey;
    private Set<String> excludedPacks;
    private boolean minifyJson;
    private boolean optimizePng;
    private boolean optimizeOgg;
    private boolean optimizeExcluded;
    private String ffmpeg;
    private Map<String, List<String>> mergedPacks;

    @Override
    public void onLoad() {
        this.encrypter = new ResourcePackEncrypter(this.getLogger());
    }

    @Override
    public void onEnable() {
        this.saveDefaultConfig();

        this.encryptionKey = resolveEncryptionKey(this.getConfig());
        this.excludedPacks = resolveExcludedPacks(this.getConfig());
        this.minifyJson = this.getConfig().getBoolean("minify-json", true);
        this.encrypter.setStripPaths(this.getConfig().getStringList("strip-paths"));
        this.encrypter.setCompressUi(this.getConfig().getBoolean("compress-ui", false));
        this.optimizePng = this.getConfig().getBoolean("optimize-png", true);
        this.optimizeOgg = this.getConfig().getBoolean("optimize-ogg", false);
        this.ffmpeg = this.getConfig().getString("ffmpeg", "ffmpeg");
        this.optimizeExcluded = this.getConfig().getBoolean("optimize-excluded-packs", false);
        this.mergedPacks = resolveMergedPacks(this.getConfig());
        if (this.getConfig().getBoolean("auto-encrypt-packs", true)) {
            // Right away, not on the first tick: plugins are enabled before the server opens its
            // network, so no client can ever be handed the plain packs while they are encrypted.
            this.encryptLoadedPacks();
        }
    }

    private String resolveEncryptionKey(Config config) {
        String key = config.getString("encryption-key", "");
        if (key.isEmpty()) {
            key = createEncryptionKey();
            config.set("encryption-key", key);
            this.saveConfig();
            this.getLogger().info("Generated and saved a new 32-char encryption key in config.yml");
        }

        if (key.length() != 32) {
            throw new IllegalArgumentException("Config encryption-key must be exactly 32 characters, got " + key.length());
        }

        return key;
    }

    /**
     * Packs listed under {@code excluded-packs} are left untouched and keep being served in plain text.
     * Entries are file names from the resource_packs folder, matched without case and without extension.
     */
    private Set<String> resolveExcludedPacks(Config config) {
        if (!config.exists(EXCLUDED_PACKS_KEY)) {
            config.set(EXCLUDED_PACKS_KEY, new ArrayList<String>());
            this.saveConfig();
        }

        Set<String> excluded = new LinkedHashSet<>();
        for (String entry : config.getStringList(EXCLUDED_PACKS_KEY)) {
            String normalized = normalizePackName(entry);
            if (!normalized.isEmpty()) {
                excluded.add(normalized);
            }
        }

        if (!excluded.isEmpty()) {
            this.getLogger().info("Packs excluded from encryption: " + String.join(", ", excluded));
        }
        return excluded;
    }

    /**
     * {@code merged-packs}: each entry is the name of a pack to build and the packs of resource_packs
     * it gathers. The client gets one pack instead of all of them; the sources stay where they are.
     */
    private Map<String, List<String>> resolveMergedPacks(Config config) {
        Map<String, List<String>> merged = new LinkedHashMap<>();
        if (!config.isSection(MERGED_PACKS_KEY)) {
            return merged;
        }
        ConfigSection section = config.getSection(MERGED_PACKS_KEY);
        for (String name : section.getKeys(false)) {
            String clean = name.trim();
            if (!clean.matches("[A-Za-z0-9_-]+")) {
                this.getLogger().warning("Merged pack name ignored (letters, digits, - and _ only): " + name);
                continue;
            }
            List<String> sources = new ArrayList<>();
            for (String source : section.getStringList(name)) {
                String normalized = normalizePackName(source);
                if (!normalized.isEmpty() && !sources.contains(normalized)) {
                    sources.add(normalized);
                }
            }
            if (sources.size() > 1) {
                merged.put(clean, sources);
            }
        }
        return merged;
    }

    private static String normalizePackName(String name) {
        String trimmed = name.trim().toLowerCase(Locale.ROOT);
        if (trimmed.endsWith(".zip")) {
            return trimmed.substring(0, trimmed.length() - 4);
        }
        if (trimmed.endsWith(".mcpack")) {
            return trimmed.substring(0, trimmed.length() - 7);
        }
        return trimmed;
    }

    private String createEncryptionKey() {
        SecureRandom random = new SecureRandom();
        StringBuilder builder = new StringBuilder(32);
        for (int i = 0; i < 32; i++) {
            builder.append(KEY_CHARS.charAt(random.nextInt(KEY_CHARS.length())));
        }
        return builder.toString();
    }

    /** A merged pack: what the merger made of its sources, and the plain pack to serve if it isn't encrypted. */
    private record Merge(PackMerger.Result result, ResourcePack plain) {}

    private void encryptLoadedPacks() {
        File resourcePacksDir = new File(PowerNukkitX.DATA_PATH, "resource_packs");
        File outputDir = new File(this.getDataFolder(), "encrypted_packs");
        File mergedDir = new File(this.getDataFolder(), "merged_packs");

        long start = System.nanoTime();
        this.clearOutputDir(outputDir);
        this.clearOutputDir(mergedDir);
        List<File> packs = listPacks(resourcePacksDir);
        List<Merge> merges = this.mergePacks(packs, mergedDir);

        int updated;
        // A quarter of the cores at most: the other servers of the machine keep running meanwhile.
        int threads = Math.max(1, Math.min(4, Runtime.getRuntime().availableProcessors() / 4));
        OggOptimizer oggOptimizer = new OggOptimizer(this.ffmpeg);
        File cache = new File(this.getDataFolder(), "cache");
        try (AssetCache pngCache = this.optimizePng ? new AssetCache(new File(cache, "png-v1"), threads, "PNG", ".png",
                     PngOptimizer::optimize, AssetCache::isCompletePng) : null;
             AssetCache oggCache = this.optimizeOgg ? new AssetCache(new File(cache, "ogg-v1"), threads, "OGG", ".ogg",
                     oggOptimizer::optimize, AssetCache::isCompleteOgg) : null) {
            updated = this.encrypter.encryptAll(packs, outputDir, this.encryptionKey, this.excludedPacks,
                    this.optimizeExcluded, this.minifyJson, pngCache, oggCache);
            if (pngCache != null) pngCache.prune();
            if (oggCache != null && oggOptimizer.isAvailable()) oggCache.prune();
        }
        if (this.optimizeOgg && !oggOptimizer.isAvailable()) {
            this.getLogger().warning("optimize-ogg: ffmpeg not found (" + this.ffmpeg + "), sounds left as they are");
        }

        this.swapPacks(merges);
        this.getLogger().info(String.format(Locale.ROOT, "%d pack(s) encrypted in %.1f s",
                updated, (System.nanoTime() - start) / 1e9));
    }

    private static List<File> listPacks(File dir) {
        List<File> packs = new ArrayList<>();
        File[] files = dir.listFiles();
        if (files == null) return packs;
        for (File file : files) {
            String name = file.getName().toLowerCase(Locale.ROOT);
            if (file.isFile() && (name.endsWith(".zip") || name.endsWith(".mcpack"))) {
                packs.add(file);
            }
        }
        packs.sort((a, b) -> a.getName().compareToIgnoreCase(b.getName()));
        return packs;
    }

    /**
     * Builds the merged packs: in {@code packs}, their sources are replaced by the merged file, which
     * is then encrypted like any other. A merge that fails leaves its sources as they are.
     */
    private List<Merge> mergePacks(List<File> packs, File mergedDir) {
        List<Merge> merges = new ArrayList<>();
        PackMerger merger = new PackMerger(this.getLogger());
        for (Map.Entry<String, List<String>> entry : this.mergedPacks.entrySet()) {
            List<File> sources = new ArrayList<>();
            for (String wanted : entry.getValue()) {
                for (File file : packs) {
                    if (normalizePackName(file.getName()).equals(wanted)) sources.add(file);
                }
            }
            if (sources.size() < 2) {
                this.getLogger().warning("Merged pack " + entry.getKey() + " skipped: less than two of its packs are in resource_packs");
                continue;
            }
            try {
                PackMerger.Result result = merger.merge(entry.getKey(), sources, new File(mergedDir, entry.getKey() + ".zip"));
                ZippedResourcePack plain = new ZippedResourcePack(result.file());
                plain.getPackId();
                packs.removeAll(sources);
                packs.add(result.file());
                merges.add(new Merge(result, plain));
            } catch (Exception e) {
                this.getLogger().error("Failed to merge " + entry.getKey() + ", its packs are sent separately", e);
            }
        }
        return merges;
    }

    private void clearOutputDir(File dir) {
        if (!dir.exists()) return;
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isFile()) {
                    file.delete();
                }
            }
        }
    }

    /**
     * Rebuilds the pack stack in its original order: each pack becomes its encrypted counterpart, and
     * the sources of a merged pack give way to it, at the place of the first one. A pack without an
     * encrypted counterpart (excluded, or failed to encrypt) is kept as-is.
     */
    @SuppressWarnings("unchecked")
    private void swapPacks(List<Merge> merges) {
        try {
            File encryptedDir = new File(this.getDataFolder(), "encrypted_packs");

            // Built before touching the manager: a failure here must not leave the server with an empty stack.
            Map<UUID, ResourcePack> encryptedById = encryptedDir.exists() ? this.loadEncryptedPacks(encryptedDir) : new HashMap<>();
            if (encryptedById.isEmpty() && merges.isEmpty()) {
                this.getLogger().warning("No encrypted pack found in " + encryptedDir.getName() + ", keeping the packs as they are.");
                return;
            }
            Map<UUID, Merge> mergeOf = new HashMap<>();
            for (Merge merge : merges) {
                for (UUID source : merge.result().sources()) mergeOf.put(source, merge);
            }

            ResourcePackManager manager = this.getServer().getResourcePackManager();

            Field packsField = ResourcePackManager.class.getDeclaredField("resourcePacks");
            packsField.setAccessible(true);
            Set<ResourcePack> packs = (Set<ResourcePack>) packsField.get(manager);

            // Chunk requests are answered from this map, not from the set: leaving it untouched
            // would keep serving the plain bytes of the old packs to clients.
            Field packsByIdField = ResourcePackManager.class.getDeclaredField("resourcePacksById");
            packsByIdField.setAccessible(true);
            Map<UUID, ResourcePack> packsById = (Map<UUID, ResourcePack>) packsByIdField.get(manager);

            List<ResourcePack> stack = new ArrayList<>(packs);
            List<ResourcePack> next = new ArrayList<>();
            Set<Merge> placed = new HashSet<>();
            int replaced = 0, folded = 0;
            for (ResourcePack original : stack) {
                Merge merge = mergeOf.get(original.getPackId());
                ResourcePack pack;
                if (merge != null) {
                    folded++;
                    if (!placed.add(merge)) continue;
                    pack = encryptedById.getOrDefault(merge.result().uuid(), merge.plain());
                    if (pack != merge.plain()) replaced++;
                } else {
                    pack = encryptedById.getOrDefault(original.getPackId(), original);
                    if (pack != original) replaced++;
                }
                next.add(pack);
            }

            packs.clear();
            packsById.clear();
            for (ResourcePack pack : next) {
                packs.add(pack);
                packsById.put(pack.getPackId(), pack);
            }

            long encrypted = next.stream().filter(p -> p.getEncryptionKey() != null && !p.getEncryptionKey().isEmpty()).count();
            this.getLogger().info("Resource packs swapped: " + next.size() + " sent (" + encrypted + " encrypted, "
                    + replaced + " rebuilt" + (folded > 0 ? ", " + folded + " merged into " + placed.size() : "")
                    + "), " + stack.size() + " loaded");
        } catch (Exception e) {
            this.getLogger().error("Failed to swap resource packs", e);
        }
    }

    private Map<UUID, ResourcePack> loadEncryptedPacks(File encryptedDir) {
        Map<UUID, ResourcePack> byId = new HashMap<>();
        File[] files = encryptedDir.listFiles();
        if (files == null) return byId;

        for (File file : files) {
            String name = file.getName().toLowerCase(Locale.ROOT);
            if (!(name.endsWith(".zip") || name.endsWith(".mcpack"))) continue;

            try {
                // The constructor already picks up the sibling <pack>.key file written by the encrypter.
                ZippedResourcePack pack = new ZippedResourcePack(file);

                File keyFile = new File(file.getAbsolutePath() + ".key");
                if (keyFile.exists()) {
                    String key = Files.readString(keyFile.toPath(), StandardCharsets.UTF_8).trim();

                    Field keyField = ZippedResourcePack.class.getDeclaredField("encryptionKey");
                    keyField.setAccessible(true);
                    keyField.set(pack, key);
                }

                // getPackId() resolves the lazy id field that hashCode() dereferences,
                // otherwise adding the pack to the manager set throws a NullPointerException.
                byId.put(pack.getPackId(), pack);
            } catch (Exception e) {
                this.getLogger().error("Failed to load encrypted pack " + file.getName() + ", keeping the original one", e);
            }
        }
        return byId;
    }
}
