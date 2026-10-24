# Sega Mega Drive / Genesis Loader for Ghidra

Ghidra loader and analysis module for Sega Mega Drive / Genesis and Sega 32X cartridge images, with
room for the Sega CD program window when an image carries one. It rebuilds the console's address space
from the ROM header, names the hardware registers, applies the header and vector-table structures, and
can disassemble the program while the code is actually executed in the BlastEm emulator.

Based on the original loader by **Dr. MefistO** ([lab313ru/ghidra_sega_ldr](https://github.com/lab313ru/ghidra_sega_ldr));
see [Credits](#credits) for authorship and for what this fork changes.

**Español:** [README_es.md](README_es.md).

---

## Contents

- [What the loader builds](#what-the-loader-builds)
- [Import options](#import-options)
- [Header verification](#header-verification)
- [Analyzer: negative offset variables](#analyzer-negative-offset-variables)
- [Live disassembly with BlastEm](#live-disassembly-with-blastem)
- [BlastEm Live panel](#blastem-live-panel)
- [Requirements and supported targets](#requirements-and-supported-targets)
- [Building](#building)
- [Installing](#installing)
- [Scripts](#scripts)
- [Repository layout](#repository-layout)
- [Known limits](#known-limits)
- [Credits](#credits)
- [What this fork changes](#what-this-fork-changes)

---

## What the loader builds

Recognising a target is what makes the loader offer itself: the image must carry `SEGA` at
`0x100`. A 32X cartridge additionally carries `MARS CHECK MODE` at `0x3C0` and is offered in both
architectures.

| Load option | Language | Used for |
| --- | --- | --- |
| Mega Drive / Genesis, Sega CD program | `68000:BE:32:MC68020` | the 68000 address space |
| 32X cartridge (second entry) | `SuperH:BE:32:SH-2` | the two SH-2 cores' view of the same image |

Everything below is created during import, before any analysis runs.

### Cartridge and system memory

| Block | Address | Content | Notes |
| --- | --- | --- | --- |
| `ROM` | `0x000000` | the image | sized from the header, never smaller than the file; readable, executable, not writable |
| `EPA` | `0x400000` | second 4 MiB window | Sega CD program area; holds file data past `0x400000` when the image is that long; created on request |
| `RAM` | `0xFF0000` | 64 KiB | work RAM, readable, writable and executable, so code the game copies there can be followed; arrives with the register blocks |
| `RAM` | `0x00FF0000` | — | byte-mapped mirror of the block above, the alias the 68000 also accepts |
| `BACKUP_RAM` | from header | up to 128 KiB | see [Import options](#import-options); volatile, not executable |
| `WORK_RAM` | from header | — | only when the header declares something other than `0xFF0000`–`0xFFFFFF`; not executable |

### Hardware registers

The register blocks are marked volatile, so Ghidra does not discard a write to the hardware as dead
code (the wide `Z80` window and `RAM` are left non-volatile). The names follow the hardware
documentation and the labels homebrew toolchains use for the same registers.

| Block | Address | Named data |
| --- | --- | --- |
| `Z80` | `0xA00000` (64 KiB) | `Z80_YM2612` at `0xA04000` |
| `SYS1` | `0xA10000` | `IO_PCBVER`, `IO_CT1_DATA`, `IO_CT2_DATA`, `IO_EXT_DATA`, `IO_CT1_CTRL`, `IO_CT2_CTRL`, `IO_EXT_CTRL`, `IO_CT1_RX`, `IO_CT1_TX`, `IO_CT1_SMODE`, `IO_CT2_RX`, `IO_CT2_TX`, `IO_CT2_SMODE`, `IO_EXT_RX`, `IO_EXT_TX`, `IO_EXT_SMODE` |
| `SYS2` | `0xA11000` | `IO_RAMMODE` |
| `Z802` | `0xA11100` | `IO_Z80BUS` |
| `Z803` | `0xA11200` | `IO_Z80RES` |
| `FDC` | `0xA12000` | `IO_FDC` (0x100 bytes) |
| `TIME` | `0xA13000` | `IO_TIME` (0x100 bytes, or 0xEC when 32X segments are present so that `0xA130EC` stays with the 32X) |
| `TMSS` | `0xA14000` | `IO_TMSS` |
| `VDP` | `0xC00000` | `VDP_DATA`, `VDP__DATA`, `VDP_CTRL`, `VDP__CTRL`, `VDP_CNTR`, `VDP__CNTR`, `VDP___CNTR`, `VDP____CNTR`, `VDP_PSG` |

The `__` variants are the upper-byte access of the same register, which 68000 code reaches by
adding 1 to the address.

### Sega 32X

With 32X segments enabled, the 68000 sees the following, and each register is named and typed:

| Block | Address | Content |
| --- | --- | --- |
| `32X_PRIV` | `0x800000` | 256 KiB |
| `32X_DRAM` | `0x840000` | 128 KiB |
| `32X_OWIMG` | `0x860000` | 128 KiB |
| `32X_ROM_FIXED` | `0x880000` | first 512 KiB of the image |
| `32X_ROM_BANK0`…`32X_ROM_BANK3` | `0x900000` + | 1 MiB each, as far as the file reaches |
| `32X_ID` | `0xA130EC` | `IO_32X_ID` |
| `32X_BANK_SET_REG` | `0xA130F1` | `IO_32X_BANK_SET_REG`, 15 words |
| `32X_SYS_REG` | `0xA15100` | `IO_32X_VDP_CTRL`, `IO_32X_ADAPTER_CTRL`, `IO_32X_SH2_INT_CTRL`, `IO_32X_BANK_CTRL`, `IO_32X_DREQ_CTRL`, `IO_32X_68K_SH2_DREQ_SRC`, `IO_32X_68K_SH2_DREQ_DEST`, `IO_32X_68K_SH2_DREQ_LEN`, `IO_32X_68K_SH2_DREQ_FIFO`, `IO_32X_SEGA_TV_REG`, `IO_32X_COMM`, `IO_32X_PWM_CTRL`, `IO_32X_CYCLE_REG`, `IO_32X_L_CH_PULSE_REG`, `IO_32X_R_CH_PULSE_REG`, `IO_32X_MONO_PULSE_REG` |
| `32X_VDP_REG` | `0xA15180` | `IO_32X_VDP_REG`, 0x80 bytes |
| `32X_PAL` | `0xA15200` | `IO_32X_PAL`, 256 words |

The second jump table of a 32X image, which sits right after the vector table and has no entry
point of its own, is disassembled as part of the import (`0x200`–`0x3C0`).

Loaded as SH-2, the same file produces the core's own map instead: `SH2_BOOT_ROM` at `0x00000000`,
`SH2_SYS_REG` at `0x00004000` with the interrupt, DREQ, communication and PWM registers named,
`SH2_VDP_REG` at `0x00004100`, `SH2_PAL` at `0x00004200`, `SH2_ROM` at `0x02000000`, `SH2_DRAM` at
`0x04000000`, `SH2_OWIMG` at `0x04020000` and `SH2_SDRAM` at `0x06000000`, each with its
cache-through alias at `+0x20000000`. The MARS user header (module name, version, source and
destination address, size, and the four SH-2 start/vector addresses) is applied at `0x8803C0`, and
`SHM_entry` and `SHS_entry` are created at the master and slave start addresses it declares.

### Structures applied to the listing

- **`VectorsTable`** at `0x000`: the 64 longwords of the exception and interrupt table, each field
  named (`SSP`, `Reset`, `BusErr`, `AdrErr`, `InvOpCode`, `DivBy0`, `Check`, `TrapV`, `GPF`,
  `Trace`, `BadInt`, `BadIRQ`, `IRQ1`, `EXT`, `IRQ3`, `HBLANK`, `IRQ5`, `VBLANK`, `IRQ7`,
  `Trap0`…`Trap15`, and the reserved slots).
- **`GameHeader`** at `0x100`: `ConsoleName`, `ReleaseDate`, `DomesticName`, `InternationalName`,
  `Version`, `Checksum`, `IoSupport`, `RomStart`, `RomEnd`, `RamStart`, `RamEnd`, `SramCode`,
  `SramStart`, `SramEnd`, `Notes`, plus a `GAME_HEADER` label, a plate comment carrying title,
  version, date, regions and controls, and the same title as the `ROM` block comment.

The vector table also seeds the first functions: every vector whose target lies in initialized,
executable, non-volatile memory becomes a function named after the vector. A vector pointing at
work RAM, at a constant, or at nothing is left alone and gets an end-of-line comment saying where it
points, which is what shipped images often do with the reserved and unused entries.

## Import options

Every choice is a real loader option. It appears in the import dialog with the value shown here and
can be set from a command line, so an import needs no interaction at all.

| Option | Dialog label | Default | Effect |
| --- | --- | --- | --- |
| `-loader-32x` | Create Sega 32X segments | on for a 32X cartridge or an SH-2 load, off otherwise | the 32X blocks and registers above |
| `-loader-sega-cd` | Create Sega CD (EPA) segment | off | the `EPA` window at `0x400000` |
| `-loader-hw-registers` | Create hardware register blocks | on | `Z80`, `SYS*`, `FDC`, `TIME`, `TMSS`, `VDP`, `RAM` and its mirror |
| `-loader-verify` | Verify the ROM header | on | the checks in [Header verification](#header-verification) |
| `-loader-sram-file <path>` | Backup RAM contents file (.srm / .sram) | empty | fills `BACKUP_RAM` from a save file |

```bash
analyzeHeadless /tmp/proj name -import game.bin -loader SegaLoader \
    -loader-32x true -loader-hw-registers true -loader-verify true \
    -loader-sram-file save.srm
```

The size of a save does not have to match the size the header declares. The block is created at the
declared size and zero filled, the file is copied over it, and any difference is reported. When the
declared backup RAM shares its window with the ROM, which is how most cartridges map it, the block is
only created if a save file is given; otherwise the address keeps showing the program and receives a
`BACKUP_RAM` label.

## Header verification

`-loader-verify` reports, without aborting the import:

- a missing `SEGA` signature at `0x100`;
- a declared ROM start other than `0`;
- a declared ROM length that disagrees with the file;
- an absent or unknown region code at `0x1F0`;
- the checksum at `0x18E`, compared against **both** rules in use: Sega's sum of 16-bit words with
  the carry folded back in, and the word-wise XOR that SGDK projects write. When the image matches
  one of them, the log says which. When it matches neither, the field gets a pre-comment with the
  declared value and both computed ones, plus a warning bookmark. A patched ROM normally keeps the
  checksum of the image it was cut from, so this is information rather than an error.

```bash
analyzeHeadless /tmp/proj name -process game.bin -noanalysis \
    -scriptPath ghidra_scripts -postScript SegaFixChecksum.java
```

`SegaFixChecksum` prints the declared value and both candidates, waits for the choice, and writes it
to `0x18E`.

## Analyzer: negative offset variables

`Negative Offset Variables` (function analyzer, from the original module) takes references of the
form `-$XXXX(Ax)` and pins them to an absolute address, which is how 68000 code on this hardware
reaches work RAM. Two options: the base register to treat, and the base address (`0xFF8000` by
default).

## Live disassembly with BlastEm

The `BlastEm Live` plugin drives the emulator and turns what it runs into code in the program that
is open, while the game plays. It relies on BlastEm's own `-l` switch: the emulator writes
`address.log` in the folder it was started from, one hexadecimal address per 68000 block it
translated. The plugin reads that file as it grows and disassembles each batch.

BlastEm logs no addresses for the Z80 machines (`sms`, `gg`, `sg`, `sc`), so live tracing covers the
68000 ones: `gen`, `32x`, `pico`, `copera`, `media`, `laser`.

Each batch is applied in a single transaction off the interface thread, and the panel counts what
happened: addresses reached, new instructions, functions created, addresses that were already code,
addresses outside the memory map, and addresses in blocks that hold no bytes yet.

## BlastEm Live panel

`Window -> BlastEm Live`, in the tool that holds the program. Enable the plugin first under
`File -> Configure` if the tool does not carry it.

| Field | Meaning |
| --- | --- |
| `ROM` | the image the emulator runs; prefilled with the file this program was imported from, and the session refuses to start on any other |
| `BlastEm` | the emulator binary; prefilled with the first `blastem` found on the PATH |
| `Machine` | the console to emulate, passed as `-m`; the list and what each one yields is below |
| `Disassemble` | how a batch of addresses becomes code; see below |
| `Trace folder` | the directory BlastEm runs in, and therefore the one that holds `address.log` |
| `Extra args` | anything else for the emulator, split the way a shell splits it |
| `RAM too` | also take the addresses that land in work or battery RAM; useful for patchers and routines the game loads into RAM, noisy otherwise |
| `follow the PC` | move the listing cursor to the last address the emulator reached |
| `pause` | keep the emulator running and keep counting, without touching the program |
| `Start` / `Stop` | begin or end the session; Stop hands the analyzers everything the session made outside their queue |
| `Ingest log…` | choose an `address.log` left behind by an earlier run and disassemble all of it |

The emulator is started as `blastem [-m machine] -l [extra args] <rom>` in the trace folder. Stop
terminates it, and so does closing the program, switching to another program, or leaving the tool, so
no orphan process is left behind.

| Mode (dialogue) | Addresses it accepts | Machine ids |
| --- | --- | --- |
| Mega Drive / Genesis (68000) | yes | `gen` |
| 32X (68000 + SuperH) | yes | `32x` |
| Pico (68000 + ARM) | yes | `pico` |
| Mega CD (68000 main CPU) | yes | `media` |
| Mega CD with Copera add-on | yes | `copera` |
| LaserActive (68000) | yes | `laser` |
| Master System (Z80) | no | `sms` |
| Game Gear (Z80) | no | `gg` |
| SG-1000 (Z80) | no | `sg` |
| SC-3000 (Z80) | no | `sc` |

The machine selection only feeds `-m`: the loader is what decides the language and the memory map of
the program being filled, so an SG-1000 or Mega CD image needs the loader support for that format
before a trace over it is worth starting.

**Disassemble** is read once, when Start is pressed:

- **auto analysis** (default): every batch goes into the analyzer's queue and the listing fills as
  soon as the tool is idle. The most complete result — functions, references, variable types and
  call chains all arrive on their own — and the slowest to show while you play.
- **immediate (experimental)**: the batch is disassembled inside its own transaction, so the
  instructions appear at once, and the analyzers are handed all the new addresses in a single pass
  when you press Stop.
- **disassemble only (experimental)**: as quick as the above, and nothing is ever asked of the
  analyzers; run `Analyze` yourself when the session ends.

The queue of the first mode only drains where a tool is listening, so a headless run always takes
the immediate route and leaves the rest for a later analysis pass.

Addresses that land in work or battery RAM are ignored unless **RAM too** is on, and even then they
become code only once the emulator's RAM has been loaded into the program: Ghidra cannot disassemble
a block that holds no bytes.

Start the session once auto-analysis has finished. The analyzer and the trace both want the program
locked for writing, and running them together is slower than either alone.

The same work can be done offline, on a log from any earlier run, with no plugin window open:

```bash
analyzeHeadless /tmp/proj name -process game.bin -noanalysis \
    -scriptPath ghidra_scripts -postScript SegaIngestAddressLog.java address.log
```

## Requirements and supported targets

- Ghidra **12.1.4**, the version whose loader API this module implements. Targets: any image whose
  header says `SEGA`, which covers Mega Drive / Genesis cartridges, 32X cartridges in either
  architecture, and images long enough to carry a Sega CD program region.
- A JDK, for building. Ghidra 12.1.4 targets Java 21, and the module is compiled for that release.
- BlastEm, only for live disassembly. The panel starts it as a child process, so it needs a display
  the emulator can open.

## Building

The build needs to know where Ghidra is, and takes it from the environment or from an untracked
`gradle.properties` next to `build.gradle`:

```properties
GHIDRA_INSTALL_DIR=/path/to/Ghidra
```

```bash
GHIDRA_INSTALL_DIR=/path/to/Ghidra ./gradlew buildExtension   # -> dist/ghidra_<version>_<date>_Sega.zip
```

The build resolves every dependency from that installation and needs no network access; add
`--offline` if you want Gradle to avoid even checking.

For iterating on the code without a zip round trip:

```bash
./scripts/dev-install.sh              # compile, then install a loose copy; restart Ghidra to pick it up
./scripts/dev-install.sh --uninstall  # remove that copy
```

The loose copy lands in `~/.config/ghidra/ghidra_<version>_PUBLIC/Extensions/Sega` and reports the
version of the Ghidra installation it was built against, so it appears in the extension list exactly
like an installed one.

The Eclipse project files of the original module are gone: the Gradle build is the way to compile it,
and GhidraDev can still be used by linking this directory as a Gradle project.

## Installing

1. Build the module zip as above.
2. `File -> Install Extensions`, press `+`, choose the zip.
3. Accept the restart Ghidra asks for.

To use the live panel, open `File -> Configure` in the tool that holds your program and enable
`BlastEm Live` under the debugger plugins if it is not already carried.

## Scripts

| Script | What it does |
| --- | --- |
| `ghidra_scripts/SegaFixChecksum.java` | shows the checksum the header declares and the two computed ones, writes the one you choose |
| `ghidra_scripts/SegaIngestAddressLog.java` | disassembles every address of a BlastEm `address.log` into the open program |

## Repository layout

```
src/main/java/sega/      loader, header, structures, checksum, analyzer
src/main/java/sega/live/ the live trace: emulator process, log reader, ingest commands, plugin and panel
ghidra_scripts/          scripts that ship with the module
data/                    reserved for runtime data (Sleigh specifications, data-type archives)
src/main/help/           Ghidra help topic
scripts/                 development install
build.gradle             module build
```

## Known limits

- Master System, Game Gear and SG-1000 / SC-3000 images are not recognized yet, and BlastEm logs no
  addresses for their Z80, so there is nothing to trace over them either. Sega CD support is limited
  to the `EPA` window of a long cartridge image: the CD program areas described by a `.cue` or `.bin`
  track are not parsed.
- Live disassembly covers the 68000 only, and covers it one translated block at a time: what BlastEm
  reports is the first address of each block, so an instruction the emulator never started a block
  with is not asked for.
- Code that runs from work RAM is reported but not disassembled until the emulator's RAM is in the
  program, because Ghidra needs bytes to disassemble.
- The trace tells Ghidra where code starts, not what the code does: functions, references and types
  still come from the analyzers, which is why *auto analysis* gives the fuller listing.
- A checksum mismatch never fails the import. A patched or trimmed ROM keeps the value of the image
  it was cut from, and the loader reports both candidates instead of guessing.

## Credits

- **Dr. MefistO** ([lab313ru](https://github.com/lab313ru)) — author of the original loader and
  analyzer, on which everything here is built.
  *Gracias por todo tu grandioso trabajo.* Thank you for all the wonderful work you have done: this
  module exists because yours did, and being able to stand on it is a privilege.
- **qufb** — the Sega 32X support carried over from the original project.
- **BlastEm** — the emulator whose `-l` trace makes the live disassembly possible, and whose sources
  settled several questions about the hardware windows this loader maps.

## What this fork changes

- Ported to the Ghidra 12.x loader API (12.1.4), including the Gradle module build and a development
  install script.
- The import dialog choices became real loader options, so imports work headless.
- Backup RAM and work RAM blocks derived from the header, with the option to load a real save file.
- The ROM block is sized from the header instead of the file length alone.
- Header and checksum verification, with both checksum rules in use, and `SegaFixChecksum`.
- Vector-table functions are only created where the vector reaches runnable code.
- The `BlastEm Live` plugin, the log reader and the batched ingest commands behind it, and
  `SegaIngestAddressLog` for working offline.

