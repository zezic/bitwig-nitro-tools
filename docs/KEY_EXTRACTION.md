# Extracting the cipher keys

`bitwig_nitro` ships **no cipher keys and no decrypted Bitwig content.** To
decrypt anything you supply the keys yourself, extracted from your own licensed
Bitwig installation. This document tells you *where the keys live* and how to
recover them. It documents the location and format of the keys, never the key
material itself.

If you do not have a licensed Bitwig install, this toolchain can still parse,
serialize, edit, and pretty-print `.nitrobin` bytes you already have in
plaintext; it just cannot decrypt anything for you.

## The three keys

There are three independent keys, for three independent cipher surfaces.

**All three are static `byte[]` literals in `bitwig.jar`, and a script in this
repository recovers them.** See
[Recovering the keys from the jar](#recovering-the-keys-from-the-jar). The
live-JVM controllers work as well, and are documented below.

Searching the jars for a key as a contiguous byte string finds nothing, in any
encoding. The arrays are built by bytecode: a `newarray byte` followed by one
`bastore` per element, so the key bytes sit one every four, interleaved with
opcodes. Reading the array out of the bytecode finds all three.

### 1. The nitro-image key

Decrypts the member payloads inside `<install>/Library/nitro-image` (the
compiled DSP archive; see
[NITRO_LOAD_MECHANISM.md](NITRO_LOAD_MECHANISM.md)). This is the key you need
to read compiled modules.

Where it lives: at runtime, Bitwig builds its cipher from a **chain of stream
transforms**. Each transform is an instance of a PRNG-based stream cipher class
(obfuscated as `BIa` on the builds examined) and carries a key field
(`key_Xzy`) and an IV-size field (`iv_size_uEK`). The nitro-image payloads use
the transform entry whose **`iv_size_uEK == 198`**; that entry's `key_Xzy` holds
the nitro-image key (a short byte string, on the order of 99 bytes on the builds
examined). A sibling entry carries the *same* key value with `iv_size_uEK == 0`,
so select by the IV-size field (198), not by position in the chain — the order
is not guaranteed stable across releases.

**This key is in the jar**, as a 99-byte array literal in the class that
declares the nitro transform chains (`com/bitwig/nitro/NitroFile`, and two
obfuscated classes that carry the same array). The chain reads

```java
new ya(new GNy[]{Krq.TUp(), new LQt(EwU, 0), new LQt(EwU, EwU.length * 2)}, 2)
```

so the `iv_size` of 198 is `99 * 2`, and the sibling entry with `iv_size == 0`
is the other `LQt` over the same array. Selecting by IV size works because that
size is derived from the key length rather than stored separately.

### 2. The Dag key

Decrypts Bitwig's `0004`-encoded document files (the encrypted `BtWg`
container). `decrypt_0004` / `read_encrypted_btwg` use it. On these files the
Dag key recovers the readable metadata section; the file body may sit behind a
further layer that this key does not open, so treat `0004` support as
metadata-level.

Where it lives: a 128-byte array literal in a class under
`com/bitwig/base/serial/file/`. The class name is obfuscated and shifts between
releases (`Tl3` on 6.1, `q2p` on 5.1.9), but the package path is not, and this
is the only long array literal under it. The method holding it ends in
`return new LQt(var1, 16)`: the Dag cipher with a 16-byte IV, which is the IV
length the `0004` container prefixes each section with.

The same value is also reachable from a live JVM, through the `ZKE.uEK ->
BIa.Xzy` field chain described below, if you prefer that route.

### 3. The nitro-std key

Decrypts the stdlib *source* members inside `<install>/Library/nitro-std`.

Where it lives: a 96-byte array literal in the same class as the nitro-image
key, in the version-1 chain:

```java
new ya(new GNy[]{Krq.TUp(), new LQt(jaQ, jaQ.length * 2)}, 1)
```

Each member is stored as `[version][iv:192][ciphertext]` and decrypts with the
same Dag routine the other two surfaces use, so this archive does **not** need
a live JVM either. `nitro-decrypt-std` and its controller take the live route.

## The cipher, for context

The Dag cipher is a keystream XOR:

```
SWC = key[16:]           # keystream key material
azd = iv + key[:16]      # per-file pad seed

transform(byte):         # the same routine encrypts and decrypts
    ... ^ SWC[i] ^ rotate_right(azd[j], counter & 7)
```

Because the per-position keystream byte depends only on the key, IV, and
position (never on the data), the transform is its own inverse. That is why
`bitwig_nitro` can re-encrypt a modified module by calling the same decrypt
routine. `dag_decrypt(data, key, iv)` in `bitwig_nitro.dag_cipher` implements
it; you provide `key` and `iv`.

## Recovering the keys from the jar

```bash
python examples/extract_keys_from_jar.py                     # report
python examples/extract_keys_from_jar.py --write             # write keys.json
python examples/extract_keys_from_jar.py --install /path/to/Bitwig
```

The script scans every class in the jar for `byte[]` literals of 48 bytes or
more (the cipher factory rejects anything shorter with `Key too short`), then
**verifies each candidate against your own installed archives** before
reporting it. A wrong key yields high-entropy noise, a right one yields content
with the structure its container promises. Candidates that verify against
nothing are reported as unidentified rather than guessed at.

There are few candidates to begin with. A 6.1 jar holds five arrays of 48+
bytes across roughly 17,000 classes: the three keys, one in the Skia shader
filesystem, and one unrelated 257-byte table.

Nothing is printed as hex unless you pass `--hex`.

**Verified on two builds.** Bitwig 5.1.9 and 6.1 carry byte-identical values
for all three keys, and all three decrypt correctly on both. Checked by
decrypting every member of each archive:

| Surface | Result |
| --- | --- |
| `nitro-image`, 6.1 | 517/517 members decompile with `decompile_nitrobin` |
| `nitro-std`, 6.1 | 121/121 members decrypt to valid UTF-8 Nitro source |
| `0004` documents | factory `.bwdevice` metadata sections decrypt and parse |

One caveat: a 5.1.9 `nitro-image` decrypts correctly under this key but does
**not** decompile, because the nitrobin container gained a field between 5.1.9
and 6.1. That is a format-version gap in the decompiler, not a key problem. The
decrypted plaintext carries the member's own name in clear and its entropy
drops from 7.8 to 4.1. The script's check looks for the member name rather than
decompiling, so it does not report a format gap as a bad key.

## keys.json

Once you have the two keys as hex strings, put them in a `keys.json`:

```json
{
  "dag_key": "<hex>",
  "nitro_image_key": "<hex>"
}
```

`bitwig_nitro.keys` resolves each key, in this order:

1. an environment variable holding a hex string:
   `BITWIG_NITRO_DAG_KEY` or `BITWIG_NITRO_IMAGE_KEY` (a direct override);
2. a `keys.json`, located via `BITWIG_NITRO_KEYS` (a full path), then
   `./keys.json` in the current directory, then `keys.json` in the per-user
   config directory, then `~/.config/bitwig-nitro/keys.json` as a portable
   fallback.

The per-user config directory follows the platform convention:
`%APPDATA%\bitwig-nitro` on Windows, `$XDG_CONFIG_HOME/bitwig-nitro` where
that variable is set, and `~/.config/bitwig-nitro` everywhere else. Set
`BITWIG_NITRO_CONFIG` to a directory to override it; the `keys.json` lookup
and `write_keys_file` then use that directory instead.

If neither source provides the requested key, `resolve_dag_key()` /
`resolve_nitro_image_key()` raise `MissingKeyError` with a message naming the
environment variable and pointing back here.

You can write the file programmatically once you have the hex:

```python
from bitwig_nitro import write_keys_file
write_keys_file(dag_key_hex="...", image_key_hex="...")
# -> keys.json in the per-user config dir  (validates the hex before writing)
```

Keep `keys.json` out of version control. It is your key material, tied to your
license.

## Running nitro-extract-keys

The live route reads the key out of a running JVM, through a small Bitwig
**controller extension** that this project bundles as package data
(`BitwigNitroKeyDump.control.js`; its source lives at
`src/bitwig_nitro/data/` in the repo). You install it, add it once in Bitwig,
let it write the key out, and the CLI reads that dump and writes your
`keys.json`:

```bash
# 1. copy the bundled controller into Bitwig's Controller Scripts directory
nitro-extract-keys --install-controller
#    (override the destination with --controllers-dir DIR)

# 2. in Bitwig: Settings -> Controllers -> Add -> "bitwig-nitro-tools /
#    Nitro Key Dump". On load it reflects over the running engine, writes the
#    key dump, and shows a popup. You can remove the controller afterward.

# 3. read the dump and write keys.json
nitro-extract-keys --live
#    --image PATH   validate against a specific nitro-image
#    --force        write even if the key fails to validate
```

The controller writes its dump to `~/.bitwig-nitro/nitro-key-dump.json`
(override with the `BITWIG_NITRO_KEYDUMP` environment variable, which both the
controller and the CLI honor). `--live` reads that file, selects the nitro-image
key from it (preferring the transform whose IV size is 198, falling back to a
value shared across the transform entries), and — if a `nitro-image` is
installed — validates the key by decrypting one member and confirming it parses
cleanly before writing `keys.json`. If the dump is missing, `--live` exits with
the install instructions above.

This is the proven recovery approach, but the live half is **yours to run**: the
controller has to load inside your own licensed Bitwig, on your own machine. The
reflection technique it uses was ported from a prototype proven on a 6.0.x
build; the shipped controller itself has not been run inside Bitwig by this
project, so whether it loads and materializes the key cleanly on your build is
what your own run confirms. See
[controller/README.md](../controller/README.md) for the controller's own notes.

The Dag key (used for `0004` document files) is not recovered by this flow;
supply it manually with `--dag-key` when you need it.

## Manual key entry

If you already have the key hex — from your own controller dump, or recovered
some other way against your own install — write it in directly, without the
controller flow:

```bash
nitro-extract-keys --image-key <hex>              # nitro-image key
nitro-extract-keys --dag-key <hex>                # Dag key (0004 documents)
nitro-extract-keys --dag-key <hex> --image-key <hex>
```

Both flags validate the hex and write `keys.json`; supply one or both.

## Transform-chain structure (background, not a key-recovery method)

The material below maps the cipher classes so you can identify them **by role**
in a live object graph. It is structure only and recovers no key by itself; the
key arrays are in the classes that build the chain, described above. Use it to
understand what the controller reflects over, or to aim your own runtime
reflection at the right objects.

Unzip `bitwig.jar` and locate the package that holds the stream-transform
classes (in `com.bitwig.nitro` / the base I/O package): the abstract transform
base, a PRNG-based stream cipher, and a transform-chain wrapper. Disassemble
them (`javap -p -c <class>`), or parse them with a class-file reader, to read the
chain's shape — each entry's key field (`key_Xzy`) and IV-size field
(`iv_size_uEK`), and the `iv_size_uEK == 198` selector that marks the
nitro-image entry. For the Dag key the live object is reached through the
`ZKE.uEK -> BIa.Xzy` field chain (obfuscated names shift between releases;
identify the classes by role, not by name, using the disassembly as a map).

The key values **are** in the class files, as the array literals described
above. The fields on the transform objects are empty on disk because the
constructor is handed the array, and the array is a constant in the class that
declares the chain, not in the cipher class.

To find the cipher class and confirm the routine by eye: its
rotate-right-by-`(n & 7)` step compiles to an `iushr` / `bipush 8` / `isub` /
`ishl` / `ior` window, and exactly one class in the jar contains that window
(`QMl` on 6.1, `pPi` on 5.1.9). The class that constructs it is the chain
wrapper, and the class that constructs *that* holds the key.

**Verify.**

Once you have written `keys.json`, confirm the nitro-image key by decrypting one
member and parsing it:

```python
from bitwig_nitro import read_entry, decompile_nitrobin
plain = read_entry(None, "filter/SallenKey.nitrobin")   # uses nitro_image_key
ast   = decompile_nitrobin(plain)                        # clean parse == right key
```

A wrong key yields high-entropy garbage that fails to parse; a right key yields
a `.nitrobin` that parses to clean EOF.

## Reverse-engineering provenance

The location claims above come from disassembling `bitwig.jar` and the audio
engine binary on a licensed install. `bitwig.jar` is heavily obfuscated
(three-character class names that change per release), but enough structure is
recoverable to locate the transform chain and the cipher classes by role. The
key material itself is never included in this repository, and you should not
publish yours. Extract from your own install, keep the keys local, and use them
only against content you are licensed to run.
