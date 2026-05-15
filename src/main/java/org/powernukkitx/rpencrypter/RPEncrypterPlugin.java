package org.powernukkitx.rpencrypter;

import cn.nukkit.Nukkit;
import cn.nukkit.plugin.PluginBase;
import cn.nukkit.scheduler.PluginTask;
import cn.nukkit.utils.Config;
import org.powernukkitx.rpencrypter.utils.ResourcePackEncrypter;

import java.io.File;
import java.security.SecureRandom;

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
        File resourcePacksDir = new File(Nukkit.DATA_PATH, "resource_packs");
        int updated = this.encrypter.encryptAllInDirectory(resourcePacksDir, this.encryptionKey);

        this.getServer().getResourcePackManager().reloadPacks();
        this.getLogger().debug("Encryption finished. Encrypted/updated packs: " + updated);
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
