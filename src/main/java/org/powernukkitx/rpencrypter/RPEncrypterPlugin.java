package org.powernukkitx.rpencrypter;

import org.powernukkitx.PowerNukkitX;
import org.powernukkitx.plugin.PluginBase;
import org.powernukkitx.scheduler.PluginTask;
import org.powernukkitx.utils.Config;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class RPEncrypterPlugin extends PluginBase {
    private static final String KEY_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[]{}()!?@#$%^&*+-_=.:,;";
    private static final String EXCLUDED_PACKS_KEY = "excluded-packs";

    private ResourcePackEncrypter encrypter;
    private String encryptionKey;
    private Set<String> excludedPacks;

    @Override
    public void onLoad() {
        this.encrypter = new ResourcePackEncrypter(this.getLogger());
    }

    @Override
    public void onEnable() {
        this.saveDefaultConfig();

        this.encryptionKey = resolveEncryptionKey(this.getConfig());
        this.excludedPacks = resolveExcludedPacks(this.getConfig());
        if (this.getConfig().getBoolean("auto-encrypt-packs", true)) {
            this.getServer().getScheduler().scheduleDelayedTask(new EncryptTask(this), 1);
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

    private void encryptLoadedPacks() {
        File resourcePacksDir = new File(PowerNukkitX.DATA_PATH, "resource_packs");
        File outputDir = new File(this.getDataFolder(), "encrypted_packs");

        this.clearOutputDir(outputDir);
        int updated = this.encrypter.encryptAllInDirectory(resourcePacksDir, outputDir, this.encryptionKey, this.excludedPacks);

        this.swapWithEncryptedPacks();
        this.getLogger().debug("Encryption finished. Encrypted/updated packs: " + updated);
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
     * Replaces every loaded pack by its encrypted counterpart, keeping the original stack order.
     * A pack without an encrypted counterpart (excluded, or failed to encrypt) is kept as-is.
     */
    @SuppressWarnings("unchecked")
    private void swapWithEncryptedPacks() {
        try {
            File encryptedDir = new File(this.getDataFolder(), "encrypted_packs");
            if (!encryptedDir.exists()) return;

            // Built before touching the manager: a failure here must not leave the server with an empty stack.
            Map<UUID, ResourcePack> encryptedById = this.loadEncryptedPacks(encryptedDir);
            if (encryptedById.isEmpty()) {
                this.getLogger().warning("No encrypted pack found in " + encryptedDir.getName() + ", keeping the packs as they are.");
                return;
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
            packs.clear();
            packsById.clear();

            int swapped = 0;
            for (ResourcePack original : stack) {
                UUID id = original.getPackId();
                ResourcePack pack = encryptedById.getOrDefault(id, original);
                if (pack != original) {
                    swapped++;
                }
                packs.add(pack);
                packsById.put(id, pack);
            }

            this.getLogger().info("Resource packs swapped with their encrypted version: " + swapped + "/" + stack.size());
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

    private static final class EncryptTask extends PluginTask<RPEncrypterPlugin> {
        private EncryptTask(RPEncrypterPlugin owner) {
            super(owner);
        }

        @Override
        public void onRun(int currentTick) {
            this.getOwner().encryptLoadedPacks();
        }
    }
}
