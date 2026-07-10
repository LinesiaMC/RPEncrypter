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
import java.util.Set;

public final class RPEncrypterPlugin extends PluginBase {
    private static final String KEY_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[]{}()!?@#$%^&*+-_=.:,;";

    private ResourcePackEncrypter encrypter;
    private String encryptionKey;

    @Override
    public void onLoad() {
        this.encrypter = new ResourcePackEncrypter(this.getLogger());
    }

    @Override
    public void onEnable() {
        this.saveDefaultConfig();

        this.encryptionKey = resolveEncryptionKey(this.getConfig());
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
        int updated = this.encrypter.encryptAllInDirectory(resourcePacksDir, outputDir, this.encryptionKey);

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

    @SuppressWarnings("unchecked")
    private void swapWithEncryptedPacks() {
        try {
            File encryptedDir = new File(this.getDataFolder(), "encrypted_packs");
            if (!encryptedDir.exists()) return;

            ResourcePackManager manager = this.getServer().getResourcePackManager();

            Field packsField = ResourcePackManager.class.getDeclaredField("resourcePacks");
            packsField.setAccessible(true);
            Set<ResourcePack> packs = (Set<ResourcePack>) packsField.get(manager);

            packs.clear();

            File[] files = encryptedDir.listFiles();
            if (files != null) {
                for (File file : files) {
                    String name = file.getName().toLowerCase();
                    if (name.endsWith(".zip") || name.endsWith(".mcpack")) {
                        ZippedResourcePack pack = new ZippedResourcePack(file);

                        File keyFile = new File(file.getAbsolutePath() + ".key");
                        if (keyFile.exists()) {
                            String key = Files.readString(keyFile.toPath(), StandardCharsets.UTF_8).trim();

                            Field keyField = ZippedResourcePack.class.getDeclaredField("encryptionKey");
                            keyField.setAccessible(true);
                            keyField.set(pack, key);
                        }

                        packs.add(pack);
                    }
                }
            }

            this.getLogger().debug("Successfully swapped resource packs with encrypted versions from encrypted_packs folder.");
        } catch (Exception e) {
            this.getLogger().error("Failed to swap resource packs", e);
        }
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
