# RPEncrpyter

Resource pack encryptor for PowerNukkitX

---

## Features
- Auto encrypts resource packs
- You can put keys into config.yml
- No effort for .key files
- Any pack can be kept unencrypted through `excluded-packs`
- JSON files are minified and PNG files re-encoded without loss before encryption (encrypted bytes no longer compress)
- Packs are encrypted before the server opens its network: the plain packs are never served
- Several packs can be sent as one (`merged-packs`): fewer packs for the client to download and load
- Files the game never reads can be left out of the encrypted packs (`strip-paths`)

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
# Re-encode the PNG files of the encrypted packs in their smallest form, pixel for pixel identical.
optimize-png: true
# Paths left out of the encrypted packs (prefixes), for files the game never reads.
strip-paths:
  - server_assets/
# Packs sent as one: the merged pack's name, then the packs it gathers.
merged-packs:
  MyEvents:
    - EventPackOne
    - EventPackTwo
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