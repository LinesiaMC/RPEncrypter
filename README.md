# RPEncrpyter

Resource pack encryptor for PowerNukkitX

---

## Features
- Auto encrypts resource packs
- You can put keys into config.yml
- No effort for .key files
- Any pack can be kept unencrypted through `excluded-packs`
- JSON files are minified before encryption (encrypted bytes no longer compress)

---

## Configuration

```yaml
auto-encrypt-packs: true
# Must be exactly 32 characters. Leave empty to auto-generate on first startup.
encryption-key: ""
# Packs that must stay readable: served as-is, without encryption.
# File names from the resource_packs folder, case-insensitive, extension optional.
excluded-packs:
  - MyPublicPack.zip
# Strip indentation and comments from the JSON files of the encrypted packs.
minify-json: true
```

---

## Getting Started

### Installation
1. Download the latest release from [RPEncrypter](https://github.com/PowerNukkitX-Bundle/RPEncrypter/releases).
2. Place the JAR file into the `plugins` folder of your PowerNukkitX server.
3. Start or reload your server.

---

## License
[LICENSE](./LICENSE)

---