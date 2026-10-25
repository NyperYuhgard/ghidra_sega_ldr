# Sega Loader for Ghidra

Ghidra loaders and analysis module for Sega cartridge and disc images: Mega Drive / Genesis and Sega
32X, with room for the Sega CD program window when an image carries one, Master System and Game Gear,
SG-1000 and SC-3000, and the two 68000 processors of a Sega CD disc. Each one rebuilds the console's
address space from the ROM or disc header, names the hardware registers, applies the header and
vector-table structures, and can disassemble the program while the code is actually executed in the
BlastEm emulator — memory the emulator's RAM holds and the image does not is asked of the emulator's
own debugger.

How far each of these has been taken: the Mega Drive / Genesis and the Master System and Game Gear are
the ground the module has been checked against, with images of each; the Sega CD is **experimental
support for the moment**; and the SG-1000 and SC-3000 have never been read from a real cartridge — their
[section](#sg-1000-and-sc-3000-need-testing) says so in as many words.

Based on the original loader by **Dr. MefistO** ([lab313ru/ghidra_sega_ldr](https://github.com/lab313ru/ghidra_sega_ldr));
see [Credits](#credits) for authorship and for what this fork changes.

**Español:** [README_es.md](README_es.md).

---

## Contents

- [What the loader builds](#what-the-loader-builds)
- [Master System and Game Gear](#master-system-and-game-gear)
- [SG-1000 and SC-3000 (Need Testing)](#sg-1000-and-sc-3000-need-testing)
- [Sega CD](#sega-cd)
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

The module installs one loader per family, and one per processor where a machine runs two: the
executable format recorded in a program is the loader's name, and each console needs its own language
and address space.

| Loader | Recognising a target | Language |
| --- | --- | --- |
| `SegaLoader` — *Sega Mega Drive / Genesis Loader* | `SEGA` at `0x100` | `68000:BE:32:MC68020` |
| | a 32X cartridge additionally carries `MARS CHECK MODE` at `0x3C0`, and is offered a second time | `SuperH:BE:32:SH-2` |
| `SegaSmsLoader` — *Sega Master System / Game Gear Loader* | `TMR SEGA` at `0x7FF0`, else at `0x3FF0`, else at `0x1FF0` | `z80:LE:16:default` |
| `SegaSg1000Loader` — *Sega SG-1000 / SC-3000 Loader* | nothing in the image: the extension names the machine, `.sg` and `.sg1` for the SG-1000, `.sc`, `.sf7` and `.sc3` for the SC-3000 | `z80:LE:16:default` |
| `SegaCdMainLoader` — *Sega CD Loader (Main 68000)* | `SEGADISCSYSTEM` at `0x0` or `0x10` of an image, or a `.cue` sheet whose dump carries it | `68000:BE:32:MC68020` |
| `SegaCdSubLoader` — *Sega CD Loader (Sub 68000)* | the same disc, and has to be asked for by name | `68000:BE:32:MC68020` |
| `SegaCdMmdLoader` — *Sega CD Loader (Disc Member)* | one file of that disc's volume, which has to be named, with the address it is placed at | `68000:BE:32:MC68020` |

Everything under this heading is created during import, before any analysis runs, and covers the 68000
machines. The 8-bit ones have their own sections:
[Master System and Game Gear](#master-system-and-game-gear) and
[SG-1000 and SC-3000](#sg-1000-and-sc-3000-need-testing), and so does the disc: [Sega CD](#sega-cd).

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
| `FDC` | `0xA12000` | `IO_FDC` (0x100 bytes); left out for a Sega CD disc, whose ASIC answers there instead |
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

Every structure this module knows lives in a category of its own — `/Sega`, and `/Sega/Sega CD` for the
disc — so a project that holds two cartridges of one family keeps one definition of each rather than one
per import.

| Structure | Category | Where it goes | What it describes |
| --- | --- | --- | --- |
| `VectorsTable` | `/Sega` | `0x000` of a 68000 cartridge | the 64 longwords of the exception and interrupt table, each field named (`SSP`, `Reset`, `BusErr`, `AdrErr`, `InvOpCode`, `DivBy0`, `Check`, `TrapV`, `GPF`, `Trace`, `BadInt`, `BadIRQ`, `IRQ1`, `EXT`, `IRQ3`, `HBLANK`, `IRQ5`, `VBLANK`, `IRQ7`, `Trap0`…`Trap15`, and the reserved slots) |
| `GameHeader` | `/Sega` | `0x100` | `ConsoleName`, `ReleaseDate`, `DomesticName`, `InternationalName`, `Version`, `Checksum`, `IoSupport`, `RomStart`, `RomEnd`, `RamStart`, `RamEnd`, `SramCode`, `SramStart`, `SramEnd`, `Notes`, plus a `GAME_HEADER` label, a plate comment carrying title, version, date, regions and controls, and the same title as the `ROM` block comment |
| `MARSUserHeader` | `/Sega` | `0x3C0`, or `0x8803C0` when the same file is loaded as SH-2 | the 32X user header: module name, version, source and destination address, size, and the four SH-2 start and vector addresses |
| `SmsHeader` | `/Sega` | the offset that carried `TMR SEGA` | the 8-bit cartridge header, with a `SMS_HEADER` label and its region, product code and declared size in the `ROM` block comment |
| `VdpWindow` | `/Sega` | kept in the catalogue | the 18 bytes of the video chip's window at `0xC00000`, spelled with the names the block already carries |
| `CdHeader` | `/Sega/Sega CD` | kept in the catalogue | the 512 bytes a disc puts in front of its data |

The last two are registered and not laid over the listing on purpose: Ghidra refuses to define a data
unit over memory that holds no bytes, and those two windows are a register file and the header sector of
a disc. Each import says in the log where the bytes of the one it is about are, and the `VDP` block keeps
its names either way.

The vector table also seeds the first functions: every vector whose target lies in initialized,
executable, non-volatile memory becomes a function named after the vector. A vector pointing at
work RAM, at a constant, or at nothing is left alone and gets an end-of-line comment saying where it
points, which is what shipped images often do with the reserved and unused entries.

## Master System and Game Gear

The two 8-bit machines share a cartridge header and an address space, so one loader covers both; the
region nibble of the header decides which console's ports get built. The image is loaded from offset 0
and the Z80 sees 64 KiB, so the pages of a large cartridge cannot all be placed at once.

### Cartridge pages

| Block | Address | Content |
| --- | --- | --- |
| `ROM` | `0x0000`–`0x7FFF` | the first two pages of the file, where the console starts; readable, executable |
| `ROM_BANK2` | `0x8000`–`0xBFFF` | page 2: the window the mapper moves, left in place until the game writes to `0xFFFC` |
| `ROM_BANK3`… | `0x8000`–`0xBFFF`, as overlays | every further 16 KiB page, one overlay each, with its file offset in the block comment |
| `RAM` | `0xC000`–`0xDFFF` | the 8 KiB of system RAM, which the console mirrors over `0xC000`–`0xFFFF`; volatile, not executable |
| `RAM_ECHO` | `0xE000`–`0xFFFB` | byte-mapped mirror of the top of that RAM |
| `MAPPER` | `0xFFFC`–`0xFFFF` | `MAPPER_PAGE1`, `MAPPER_PAGE2`, `MAPPER_PAGE3`: the bank number of the three windows, written as bytes; volatile |
| `CART_RAM` | `0x8000`–`0xBFFF`, as an overlay | only when a save file is given: the battery or extra RAM of a cartridge sits in the window the mapper moves |

A 32 KiB image needs no mapper and produces the `ROM` block alone; a shorter one is still loaded and the
log says how much of the mirror the file cannot fill.

The overlays are the one compromise here made to Ghidra rather than to the hardware: the console keeps
one page in that window at a time, and the memory map window is where you pick the page a running game
had paged in.

### Ports

The port blocks live in the `io` space of the Z80 language and are volatile. The decoder turns an
immediate port number into a constant, so they collect no references from the code; what they give a
port you reach through a register, or find by hand, is a name and a type.

| Block | Ports | Named |
| --- | --- | --- |
| `VDP` | `0x80`–`0xBF` | `VDP_DATA` at `0xBE`, `VDP_CTRL` at `0xBF` — data on even addresses, control and status on odd |
| `PSG` | `0x40`–`0x7F` | `PSG_WRITE` at `0x7F`, `HV_COUNTER_H` at `0x40`, `HV_COUNTER_V` at `0x41` — writes reach the tone generator, reads return the latched raster position |
| `CONTROLLER` | `0xC0`–`0xFF` | `IO_DATA_AB` at `0xDC`, `IO_CTRL` at `0xDD`, and the same pair at `0xC0` and `0xC1` |
| `IO_CONTROL` | `0x00`–`0x3F`, or `0x08`–`0x3F` on Game Gear | the latch that makes the controller lines and the raster position update |
| `GG_IO` | `0x00`–`0x06`, Game Gear only | `GG_START_REGION`, `GG_IO_DATA`, `GG_IO_CTRL`, `GG_SERIAL_OUT`, `GG_SERIAL_RX`, `GG_SERIAL_CTRL`, `PSG_PAN` |

### Header and entry points

- **`SmsHeader`** at the offset that carried the signature — `SMS_HEADER` label, and a plate comment
  with the region, version, product code, declared checksum and its range, and the size of the image in
  pages. The same region and product code go into the `ROM` block comment.
- **The program** is disassembled from `0x0000`: the reset vector of these consoles holds nothing but a
  jump and the Z80 language follows it. `NMI_ISR` is created at `0x66` and `RST_08` … `RST_38` at the
  restart addresses.
- **`-loader-verify`** adds the checks of [Header verification](#header-verification) for this format:
  the region nibble's idea of the ROM size against the file, the Sega checksum, and the Codemasters
  one where the cartridge carries it.

The Sega checksum is a byte sum over `0x0000` to the header and then over `0x8000` to the size the range
nibble describes, folded into 16 bits. Codemasters cartridges use their own header just before the Sega
one — a word sum over the file with the Sega header excluded, and a checksum that pages through writes
to `0x0000`, `0x4000` and `0x8000` instead of `0xFFFC`–`0xFFFF`. Both are reported, and neither aborts the
import: only the export Master System BIOS refuses to start a game whose checksum does not match, so a
Game Gear or Japanese image often carries a field the console never reads.

## SG-1000 and SC-3000 (Need Testing)

The two computers that came before the Master System have the Z80 in common and little else: the SG-1000
decodes its cartridge and its ports one way, the SC-3000 another, and the latter has an 8255 next to the
video chip. **Neither has been loaded from a real cartridge.** The map comes from the sources of an
emulator, and the machine is taken from the extension of the file, because a cartridge of either computer
puts nothing in front of its program: the image says nothing about the machine it was written for. Every
import of this loader writes both facts into its log, and the comment of the `ROM` block ends with
*map taken from the emulator's sources, not from a cartridge*. And neither has been carried into a window:
what has been measured is the headless import of the images this repository makes for itself.

### The map, and the extension that picks it

| Extension | Machine |
| --- | --- |
| `.sg`, `.sg1` | SG-1000 |
| `.sc`, `.sf7`, `.sc3` | SC-3000 |

A file with any other name is not offered this loader, and the two that read a header of their own keep
whatever they recognise: an SG-1000 image left named `.sms` is imported as a Master System cartridge
whose checksum nothing answers.

| Block | Address | Content |
| --- | --- | --- |
| `ROM` | `0x0000`, the window ends at `0xBFFF` | the cartridge from file offset 0; readable, executable |
| `ROM_ECHO`… | above it, in the same window | the mirrors the console makes when the image is shorter than the window it has to fill |
| `RAM` | `0xC000`–`0xDFFF` | the 8 KiB of the machine; volatile, not executable |
| `RAM_ECHO` | `0xE000`–`0xFFFF` | byte-mapped echo of that RAM, which is what the console answers with over its own top 16 KiB |
| `ROM_BANK1`…`ROM_BANKn`, `MAPPER` | `0x400`, `0x4000`, `0x8000`, `0xFFFC` | only for an image bigger than the window, and then it is the Master System's paging that places it: the log says so in as many words, because neither of these computers had a mapper |

The window is `0xC000` bytes and the console mirrors the cartridge over it with the mask of the nearest
power of two above the length of the image, so a 16 KiB file arrives four times. Those repeats are placed
as byte-mapped aliases rather than as copies, and the log counts them. The count stops at sixteen
mirrors, and says that it stopped.

`NMI_ISR` is created at `0x66` and `RST_08` … `RST_38` at the restart addresses, and the disassembly
starts at `0x0000`: power on leaves the Z80 there, with interrupts held off, which is where a cartridge of
either machine puts its first instruction.

### Ports of each machine

The port blocks are in the `io` space of the Z80 language, volatile and without bytes, exactly as in
[Ports](#ports) for the Master System; what they hold is the range the emulator gives each chip, and the
name of every address that one program of the time decodes by its number.

| Machine | Block | Ports | Named |
| --- | --- | --- | --- |
| SG-1000 | `CONTROLLER` | `0x00`–`0x3F` | — an odd address writes both controller ports and latches the raster counter |
| | `PSG` | `0x40`–`0x7F` | `HV_COUNTER_H` at `0x40`, `HV_COUNTER_L` at `0x41` — any address of the range writes the tone generator |
| | `VDP` | `0x80`–`0xBF` | `VDP_DATA` at `0x80`, `VDP_CTRL` at `0x81` — the chip is decoded by the parity of the address |
| | `CONTROLLER_DATA` | `0xC0`–`0xFF` | `IO_DATA_AB_ALT` at `0xC0`, `IO_CTRL_ALT` at `0xC1`, `IO_DATA_AB` at `0xDC`, `IO_CTRL` at `0xDD` — anything else reads as `0xFF` |
| SC-3000 | `PPI_VDP` | `0x00`–`0x1F` | the 8255 read with the video data port wired into it |
| | `VDP_PSG` | `0x20`–`0x3F` | the video chip by parity, and a write reaches the tone generator with it |
| | `PPI_PSG` | `0x40`–`0x5F` | the 8255 by its two low bits, and a write reaches the tone generator with it |
| | `PSG` | `0x60`–`0x7F` | any address writes the tone generator, and nothing is read here |
| | `PPI_VDP2` | `0x80`–`0x9F` | the 8255 read with the video data port wired into it, and written through both |
| | `VDP` | `0xA0`–`0xBF` | `VDP_DATA` at `0xA0`, `VDP_CTRL` at `0xA1` — the one range that holds nothing else |
| | `PPI` | `0xD0`–`0xFF` | the 8255's port A, port B, port C and control register, in that order and again every four addresses |

The 8255 is selected by two address lines rather than by a number of its own, which is why its registers
are described in the comment of the block and not labelled four times: no image of this family says which
of those addresses a given program uses.

`-loader-hw-registers` decides whether the port blocks are built at all, and `-loader-verify` has nothing
to check here — the log of a load says that too, rather than going quiet.

## Sega CD

A disc is two programs on two 68000 processors that reach the same memories through one ASIC, and each
of them sees those memories at a different address. So a disc gets two views, and the loader an import
names is what chooses between them.

**The support of a Sega CD is experimental for the moment.** The disc, the sheet that describes it, the
volume of files it carries and the two address spaces are written, and they are measured by the command
line against a real disc; what they have not had is the use in a window that the cartridge loaders have
had.

### Two loaders, one disc

| View | Loader | What it is given |
| --- | --- | --- |
| the console | `SegaCdMainLoader` — *Sega CD Loader (Main 68000)* | the CD boot ROM where a cartridge would sit, program RAM through the window the console reaches, the word RAM and the cell image, the port region with the ASIC in it, and the work RAM with the program that booted with the disc |
| the drive | `SegaCdSubLoader` — *Sega CD Loader (Sub 68000)* | all 512 KiB of program RAM with the disc's own program in it, the word RAM through both of its windows, the battery RAM, the sound memory, and the ASIC at the top of the address space |

An import that names no loader lands in the view of the processor the console runs, because that is the
one a program of the disc is written for. The drive's own view is asked for with
`-loader SegaCdSubLoader`, or picked from the loader list of the import dialog. One program in Ghidra is
one processor, so both views of one disc mean importing the image twice.

A third loader, `SegaCdMmdLoader`, makes a program of one *file* of the disc rather than of the disc: see
[Disc members](#disc-members).

### The disc, and what is read from it

An image is accepted when its first bytes, or the bytes sixteen past them, are `SEGADISCSYSTEM`: a track
of 2048-byte sectors, or a raw dump of 2352-byte ones. A `.cue` sheet is accepted too, however the ripper
headed it — a `CATALOG` number, a `REM` comment, a genre or a date may all come before anything else —
and however it divides the disc: each `FILE` of stored bytes that the sheet names is opened, with the
quoted names that carry spaces and parentheses, and the track whose dump holds the signature is the one
that gets read. Its `INDEX 01` says where the track begins; when the bytes disagree with the sheet, the
signature is what is believed and the import log says how far apart the two were. Tracks of audio are
passed over, and so is a dump kept as a `MOTOROLA` sheet instead of stored bytes, which cannot be read one
sector at a time.

What the loader takes out of the disc is three things small and fixed, and one that is neither:

- the **first sector**, `0x800` bytes of header, read for its device and region fields, its version, its
  release date and its two program areas;
- the **program of the drive**, from the disc address and length of the first pair (`0x40` and `0x44`),
  placed where that processor runs it;
- the **program of the console**, which is not a promise the disc makes: the boot stage always takes
  1.5 KiB from `0x200` of the disc and puts them at the bottom of the work RAM, where they then ask the
  drive for the rest of the game;
- the **list of the files** the disc carries in its volume, which every import of a disc writes to its
  log, sector and length of each, directories and all — see [Disc members](#disc-members).

The second pair of the header (`0x48` and `0x4c`) is read, and said out loud whenever it stands empty or
holds a place other than that one: no sheet makes the console read from where it says, so a disc gets
reported and believed no further.

### Disc members

Under its programs a Sega CD disc is an ISO-9660 volume, and inside that volume a game keeps small
programs for the console's own 68000: the files named `.MMD` that it loads into RAM and runs, next to the
`.BIN` data, the `.STM` streams and the `.TXT` of the same volume.

`SegaCdMmdLoader` imports one of those files as a program of its own, on the map of the console — the
blocks [Cartridge-side view](#cartridge-side-view) describes, so the references the member makes into the
memories around it land on a name:

```bash
analyzeHeadless proj name -import game.cue -loader SegaCdMmdLoader \
    -loader-cd-mmd ATTACK.MMD -loader-cd-mmd-address 0xFF2000
```

**The disc does not say where a member is loaded.** The head of a `.MMD` is not a table of vectors, and
the addresses inside it name the work RAM, the word RAM, the cart and the drive all at once: nothing the
disc holds fixes the place, so the address is asked for and the log says, in as many words, that the one
it got is the one that was given. It is read as `ff2000`, `0xff2000` or `$ff2000`, and has to reach no
further than `0xFFFFFF`. The name is matched the way a volume spells it: upper case, the `;1` left off,
the extension only when nothing else answers to the same stem, and the directory in front of it when two
files share a name.

The dialog asks for the same thing, and the disc's own program is not where a member turns up: with the
`.cue` chosen, switch **Format** from *Sega CD Loader (Main 68000)* to *Sega CD Loader (Disc Member)*
and press `Options…`; the two fields it shows under *The member of the volume* answer for the disc —
the name one opens on the files the volume holds, standing on the first `.MMD` of it, and the address
one is what is left to type. Format first and `Options…` after: the dialog empties whatever was written
as soon as the loader changes, and what was answered comes back for the next import of the same
project. An import that names no file at all takes the one the box stands on, and says which in the
log. A member is a program of its own, so a hundred files mean a hundred imports, and the names
worth choosing are the ones every Sega CD import writes into its log. A file taken off the disc
beforehand is not a way in: a `.MMD` carries nothing that says what it is, so it has to be read through
the disc it came from.

What arrives is a block named after the file with a function at its first byte, and every window of
memory that held it is cut to the parts that are left — `WORK_RAM_FREE` becomes two blocks, say — so
nothing is ever created on top of the member. A file is read up to 1 MiB and the length left out of that
is reported. A member put on registers, at `0xA12000` for instance, is named with every block it reaches
into and placed anyway, as an overlay: what an import was asked for is not for the loader to overrule.

None of this reaches back into the disc imported before it, and it is not meant to: the work RAM of that
map is created without bytes, because the disc says nothing about what a game carries there, and a
listing of `??` over `WORK_RAM_FREE` is that said out loud. Bytes for those addresses come from the
emulator's RAM, which no version of this module can hand over yet.

### Cartridge-side view

| Block | Address | Content |
| --- | --- | --- |
| `BIOS_ROM` | `0x000000`–`0x01FFFF` | the boot ROM, 128 KiB; bytes from `-loader-cd-bios`, a hole of the same size without them |
| `BIOS_ROM` | `0x040000`–`0x05FFFF` | the alias of the same ROM, only when its bytes were given |
| `PROGRAM_RAM` | `0x020000`–`0x025FFF` | the low program RAM through the window this processor is given |
| `DISC_PROGRAM` | `0x026000` + | the program of the drive, the same bytes the drive's own view shows |
| `PROGRAM_RAM_FREE` | … – `0x03FFFF` | the rest of that window |
| `WORD_RAM` | `0x200000`–`0x21FFFF` | 128 KiB of the ASIC's word RAM, the bank the gate array selects |
| `CELL_IMAGE` | `0x220000`–`0x23FFFF` | the window of that RAM the ASIC draws its on screen font from |
| `GATE_ARRAY` | `0xA12000` | the ASIC registers, where a cartridge gives a floppy controller |
| `BOOT_PROGRAM` | `0xFF0000`–`0xFF05FF` | the program that booted with the disc, and `BOOT_entry` at its first byte |
| `WORK_RAM_FREE` | `0xFF0600`–`0xFFFFFF` | the work RAM past it, in as many blocks as a member of the volume makes |

The Genesis blocks of [Hardware registers](#hardware-registers) arrive with this view — `Z80`, `SYS1`,
`SYS2`, `Z802`, `Z803`, `TIME`, `TMSS`, `VDP` — except `FDC`, whose address the ASIC holds.

### Drive-side view

| Block | Address | Content |
| --- | --- | --- |
| `PROGRAM_RAM` | `0x000000`–`0x005FFF` | the low program RAM, where the boot stage keeps this processor's vectors and workspace |
| `DISC_PROGRAM` | `0x006000` + | the program of the disc, from the address its header declares |
| `PROGRAM_RAM_FREE` | … – `0x07FFFF` | the rest of the 512 KiB this processor holds |
| `WORD_RAM` | `0x080000`–`0x0BFFFF` | 256 KiB, the whole of the ASIC's word RAM |
| `WORD_RAM_1M` | `0x0C0000`–`0x0DFFFF` | the same RAM through the window that shows only its first half |
| `BACKUP_RAM` | `0xFE0000`– | 8 KiB of battery RAM, answered on the odd addresses of a 64 KiB window; bytes from `-loader-cd-bram` |
| `BACKUP_RAM_FREE` | … – `0xFEFFFF` | the rest of that window, when the save does not fill it |
| `PCM` | `0xFF0000`–`0xFF7FFF` | the sound memory of the RF5C164, answered on odd addresses |
| `GATE_ARRAY` | `0xFF8000` | the ASIC registers |

### The ASIC, the sound chip and their names

One table of registers serves both views, at the word index times two from the base of the block:
`0xA12000` for the console, `0xFF8000` for the drive.

| Address | Register |
| --- | --- |
| `+0x00` | `GA_SUB_CPU_CTRL`, `GA_MEM_MODE`, `GA_CDC_CTRL`, `GA_CDC_REG_DATA`, `GA_CDC_HOST_DATA`, `GA_CDC_DMA_ADDR`, `GA_STOP_WATCH`, `GA_COMM_FLAG` |
| `+0x10` | `GA_COMM_CMD0`…`GA_COMM_CMD7` — the words the console puts in front of the drive |
| `+0x20` | `GA_COMM_STATUS0`…`GA_COMM_STATUS7` — the words it is answered with |
| `+0x30` | `GA_TIMER`, `GA_INT_MASK`, `GA_CDD_FADER`, `GA_CDD_CTRL` |
| `+0x38` | `GA_CDD_STATUS0`…`GA_CDD_STATUS4`, then `GA_CDD_CMD0`…`GA_CDD_CMD4` |
| `+0x4C` | `GA_FONT_COLOR`, `GA_FONT_BITS`, `GA_FONT_DATA0`…`GA_FONT_DATA3` |
| `+0x100` | `GA_SUBCODE`, the queue of subcode bytes read off the disc; `GA_SUBCODE_MIRROR` marks the repeat of the whole file at `+0x180` |

The sound chip is reached only by the drive, only on odd byte addresses, and its eight channels share one
set of registers chosen by a write to the control port: `PCM_CHANNEL_ENVELOPE`, `PCM_CHANNEL_PAN`,
`PCM_CHANNEL_FREQ_LOW`, `PCM_CHANNEL_FREQ_HIGH`, `PCM_CHANNEL_LOOP_LOW`, `PCM_CHANNEL_LOOP_HIGH`,
`PCM_CHANNEL_START` at `0xFF0001` through `0xFF000D`, then `PCM_CONTROL` at `0xFF000F` and
`PCM_CHANNEL_ENABLE` at `0xFF0011`. `PCM_WAVE_RAM` marks the samples above them, at `0xFF2001`.

### What the loader names in either view

- **The header of the disc** is not placed in memory — it is the sector the boot stage reads before any
  program exists — but its whole text plate goes into the comment of every program block it describes,
  and into the import log.
- **The entries of the boot stage** are labelled where the hardware puts them, in the low program RAM for
  the drive (`bios_common_work` at `0x5E80`, then `_setjmptbl`, `_waitvsync`, `_buram`, `_cdboot`,
  `_cdbios`, `_usercall0`–`_usercall3`, `_adrerr`, `_coderr`, `_diverr`, `_chkerr`, `_trperr`, `_spverr`,
  `_trace`, `_nocod0`, `_nocod1` and `_slevel1`–`_slevel3` up to `0x5F82`) and in the boot ROM for the
  console, when its file was given: the `_bios_*` entries from `0x280` to `0x368`, which is how a call of
  the CD application programming interface becomes a name in the listing.
- **`-loader-verify`** reports a first sector that does not open with `SEGADISCSYSTEM`, and a program of
  the drive declared inside the header sector or past what the disc holds. None of them aborts the import.

## Import options

Every choice is a real loader option. It appears in the import dialog with the value shown here and
can be set from a command line, so an import needs no interaction at all.

| Loader | Option | Dialog label | Default | Effect |
| --- | --- | --- | --- | --- |
| Genesis | `-loader-32x` | Create Sega 32X segments | on for a 32X cartridge or an SH-2 load, off otherwise | the 32X blocks and registers above |
| Genesis | `-loader-sega-cd` | Create Sega CD (EPA) segment | off | the `EPA` window at `0x400000` |
| all | `-loader-hw-registers` | Create hardware register blocks | on | `Z80`, `SYS*`, `FDC`, `TIME`, `TMSS`, `VDP`, `RAM` and its mirror, the `VDP`, `PSG`, `CONTROLLER`, `IO_CONTROL` and `MAPPER` blocks of the 8-bit machines, the port blocks of an SG-1000 or SC-3000, or the `GATE_ARRAY` and sound registers of a disc |
| all | `-loader-verify` | Verify the ROM header | on | the checks in [Header verification](#header-verification); an SG-1000 or SC-3000 cartridge carries no header, so the answer there is that there is nothing to check |
| Genesis | `-loader-sram-file <path>` | Backup RAM contents file (.srm / .sram) | empty | fills `BACKUP_RAM` from a save file |
| SMS / GG | `-loader-cart-ram-file <path>` | Cartridge RAM contents file (.sav / .sms) | empty | fills the `CART_RAM` overlay of `0x8000` from a save file |
| Sega CD | `-loader-cd-bios <path>` | CD BIOS image the console runs before the disc (.bin) | empty | fills `BIOS_ROM` and its alias in the console's view |
| Sega CD | `-loader-cd-bram <path>` | Backup RAM contents file (.brm / .bkr) | empty | fills `BACKUP_RAM` in the drive's view, spread over the odd addresses of its window |
| Disc member | `-loader-cd-mmd <name>` | Disc member to import (ISO-9660 name) | the first `.MMD` of the volume | the file of the volume to import; in the dialog it is a box holding the files the disc carries, and a name that is not one of them is answered with the list |
| Disc member | `-loader-cd-mmd-address <address>` | Address the member is loaded at | empty | where those bytes are placed, `0xFF2000` for the work RAM; required, because no disc says it |

Both of the file options of a disc are checked at import time, and a path that is not a file stops the
import with the reason rather than loading half a machine.

```bash
analyzeHeadless /tmp/proj name -import game.bin -loader SegaLoader \
    -loader-32x true -loader-hw-registers true -loader-verify true \
    -loader-sram-file save.srm

analyzeHeadless /tmp/proj name -import game.sms -loader SegaSmsLoader \
    -loader-hw-registers true -loader-verify true

analyzeHeadless /tmp/proj name -import cartridge.sg -loader SegaSg1000Loader -loader-hw-registers true

analyzeHeadless /tmp/proj name -import game.cue -loader SegaCdMainLoader \
    -loader-cd-bios bios_CD_E.bin -loader-hw-registers true -loader-verify true

analyzeHeadless /tmp/proj name -import game.cue -loader SegaCdSubLoader \
    -loader-cd-bram save.brm -loader-hw-registers true
```

The size of a save does not have to match the size the header declares. The block is created at the
declared size and zero filled, the file is copied over it, and any difference is reported. When the
declared backup RAM shares its window with the ROM, which is how most cartridges map it, the block is
only created if a save file is given; otherwise the address keeps showing the program and receives a
`BACKUP_RAM` label. A Game Gear or Master System save is up to 32 KiB and always lands in the paged
window, so the `CART_RAM` block is an overlay whether or not the file is shorter than a page.

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

For a Master System or Game Gear image the same option compares the size implied by the region
nibble with the file, and the two checksum rules those cartridges use; both are described in
[Header and entry points](#header-and-entry-points).

For a Sega CD disc it checks the signature of the first sector and the program area the header declares
for the drive, and reports the pair it does not read from; those are described in
[What the loader names in either view](#what-the-loader-names-in-either-view). A disc carries no
checksum to verify.

```bash
analyzeHeadless /tmp/proj name -process game.bin -noanalysis \
    -scriptPath ghidra_scripts -postScript SegaFixChecksum.java
```

`SegaFixChecksum` prints the declared value and both candidates, waits for the choice, and writes it
to `0x18E`. It reads the 68000 header, so a Master System or Game Gear image is left alone.

## Analyzer: negative offset variables

`Negative Offset Variables` (function analyzer, from the original module) takes references of the
form `-$XXXX(Ax)` and pins them to an absolute address, which is how 68000 code on this hardware
reaches work RAM. Two options: the base register to treat, and the base address (`0xFF8000` by
default).

## Live disassembly with BlastEm

The `BlastEm Live` plugin drives the emulator and turns what it runs into code in the program that
is open, while the game plays. It relies on BlastEm's own `-l` switch: the emulator writes a trace in the
folder it was started from, one hexadecimal address per 68000 block it translated — `address.log` for the
processor of the cartridge, `address_sub.log` for the drive's own on a disc. The plugin reads that file as
it grows and disassembles each batch.

BlastEm instruments its 68000 cores and nothing else. The Z80 of the Master System, Game Gear, SG-1000
and SC-3000 logs no addresses, and neither does the Sega media player (which has no CPU) or the NEC
processor of the LaserActive, so live tracing covers `gen`, `32x`, `32xcd`, `pico`, `copera` and a
detected Sega CD disc.

Each batch is applied in a single transaction off the interface thread, and the panel counts what
happened: addresses reached, new instructions, functions created, addresses that were already code,
addresses outside the memory map, and addresses in blocks that hold no bytes yet.

## BlastEm Live panel

`Window -> BlastEm Live`, in the tool that holds the program. Enable the plugin first under
`File -> Configure` if the tool does not carry it.

| Field | Meaning |
| --- | --- |
| `ROM` | the image the emulator runs; prefilled with the file this program was imported from — for a disc, with its `.cue` sheet rather than the track the program was built from, unless that sheet hands the disc over several files, which the panel does not start — and the session refuses to start on any other |
| `BlastEm` | the emulator binary; prefilled with the first `blastem` found on the PATH |
| `Machine` | the console to emulate, passed as `-m`; it starts on *Detect from the image* and the list, with what each one yields, is below |
| `Disassemble` | how a batch of addresses becomes code; see below |
| `Memory` | whether Ghidra asks the emulator for the memory its machine runs on: *leave RAM as it is*, *fill from its debugger (-d)* or *fill from the remote stub (-D)*; see [Filling RAM from the emulator](#filling-ram-from-the-emulator) |
| `Trace folder` | the directory BlastEm runs in, and therefore the one that holds the trace the panel reads |
| `Extra args` | anything else for the emulator, split the way a shell splits it |
| `RAM too` | also take the addresses that land in work or battery RAM; useful for patchers and routines the game loads into RAM, noisy otherwise |
| `follow the PC` | move the listing cursor to the last address the emulator reached |
| `pause` | keep the emulator running and keep counting, without touching the program |
| `Start` / `Stop` | begin or end the session; Stop hands the analyzers everything the session made outside their queue |
| `Ingest log…` | choose a trace left behind by an earlier run and disassemble all of it |
| `Fill RAM…` | ask the emulator, stopped in its debugger, for the memory windows this session's trace reached; it is dead until a session is running and `Memory` is not *leave RAM as it is* |

The emulator is started as `blastem [-m machine] -l [extra args] <rom>` in the trace folder; the `-m`
switch is left out on the first row of the list below. A chosen `Memory` channel adds `-d -t` or `-D` to
that command line. The exact command is written to the panel log, and
so is the exit code whenever the process dies before Stop is pressed. Stop terminates it, and so does
closing the program, switching to another program, or leaving the tool, so no orphan process is left
behind.

| Machine (dialogue) | `-m` | Trace |
| --- | --- | --- |
| Detect from the image | *(switch left out)* | yes, whenever the image runs a 68000 |
| Mega Drive / Genesis (68000) | `gen` | yes |
| 32X (68000 + two SH-2) | `32x` | yes, the 68000 only |
| 32X over a Sega CD disc | `32xcd` | yes, the 68000 only |
| Pico (68000) | `pico` | yes |
| Copera (68000) | `copera` | yes |
| Master System (Z80) | `sms` | no |
| Game Gear (Z80) | `gg` | no |
| SG-1000 (Z80) | `sg` | no |
| SC-3000 (Z80) | `sc` | no |
| Media player (VGM / WAV / FLAC, no CPU to trace) | `media` | no |
| LaserActive (NEC UPD78K237, no trace) | `laser` | no |

A Sega CD disc has no id of its own: BlastEm recognises it by the `SEGADISCSYSTEM` header, so the first
row is the only way to reach it. Over a disc the main 68000 writes `address.log` and the sub CPU writes
`address_sub.log`, and the panel reads whichever one belongs to the view being filled — the drive's
program is traced in the second, the console's in the first. A program built from a member of the volume
is the console's too, and so is traced in `address.log`, the same one the disc's own boot program is
filled from. The emulator needs the sheet, not the track dump the program was built from, and the `ROM`
field holds the sheet already when the program came from one. Support of a Sega CD in this panel is
experimental, though, and a sheet that hands the disc out over several files — the way a rip laid down for
a burner does — is not started at all: `Start` stays dead and the log says why. Take the disc to a single
image of its data track, an `.iso` made from the sheet, and point the field at that: BlastEm reads such an
image by its `SEGADISCSYSTEM` header, and so does the loader. A trace of the split disc from a run made
elsewhere still comes in through `Ingest log…`. Detection also tells Master System from
Game Gear by the extension of the file, so keep a Game Gear image named `.gg`.

The machine selection only feeds `-m`: the loader is what decides the language and the memory map of
the program being filled, so what you run has to be the same console the program was imported as, and
a core BlastEm does not trace — the two SH-2 of a 32X — has nothing for a trace to land in.

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
a block that holds no bytes. [Filling RAM from the emulator](#filling-ram-from-the-emulator) is how
those bytes arrive.

Start the session once auto-analysis has finished. The analyzer and the trace both want the program
locked for writing, and running them together is slower than either alone.

The same work can be done offline, on a log from any earlier run, with no plugin window open:

```bash
analyzeHeadless /tmp/proj name -process game.bin -noanalysis \
    -scriptPath ghidra_scripts -postScript SegaIngestAddressLog.java address.log
```

### Filling RAM from the emulator

A block that holds no bytes is what a listing of work RAM reads as `??`: Ghidra needs something to
disassemble, and the cartridge or disc an import read says nothing about what the machine keeps there.
The **Memory** row chooses whether Ghidra asks the emulator itself, by one of the two debug channels
BlastEm has always had.

| Choice | Switches | How the bytes come back |
| --- | --- | --- |
| *leave RAM as it is* | none | nothing is asked; this is how the panel ran before, and how it runs a game straight away |
| *fill from its debugger* | `-d -t` | a `save/b` of the window into a file in the trace folder, read back once it stops growing |
| *fill from the remote stub* | `-D` | `$m` packets, at most 255 byte(s) each, which is all one reply of that stub can carry |

Both debuggers take the machine over and leave it stopped at the reset vector, so the panel immediately
tells it to run — `c` on the debugger's own terminal, the `c` packet on the stub — and the game plays from
there. `-t` is not decoration: without it the emulator's debugger refuses a pipe for its terminal, closes
the three streams of the process and carries its prompt off to an `xterm` of its own, over two named
pipes. `-D` is the other way round and silences the emulator's text, which goes to `blastem-text.log` in
the trace folder; the trace itself is unaffected, because `-l` is written by the emulator either way.

**Fill RAM…** then asks for the windows this session's trace actually reached: every executable block of
the program's own address space that holds no bytes and that the machine ran in at least once. A window
that fits in 64 KiB is asked for whole; a bigger one gives up the span the trace touched and the log says
that the rest of it stays unknown. The bytes land on the map in one transaction:

- a block covered whole becomes initialized under the same name, with its permissions and its labels;
- a block covered in part is split around the dump, the pieces named as the disc members name theirs
  (`NAME`, then `NAME_2`), and the labels inside the window are put back where they were;
- a block that already carries bytes of the image is left alone, and counted as such: a dump of RAM cannot
  improve what the image says.

The machine has to be standing in its debugger for either channel to answer, which is what the `u` key
does while the game plays, and what a breakpoint does on its own. A request that gets nothing says so,
and names the key to press; nothing is guessed and no bytes are invented. With the stub, only the two
packets it is known to handle are ever sent — a command it does not recognise ends the emulator.

After the bytes land, the addresses of that window are looked at again and handed to the same ingest the
session uses, so the log closes with what the dump was worth: how many of the addresses it covers now have
something to disassemble, and how many were already code.

What is measured of all this are the two channels asked by the command line over one and the same window,
which answer with the same bytes. The path through the panel — choosing **Memory**, pressing
**Fill RAM…** — has not been walked in a window yet.

## Requirements and supported targets

- Ghidra **12.1.4**, the version whose loader API this module implements. Targets: any image whose
  header says `SEGA`, which covers Mega Drive / Genesis cartridges, 32X cartridges in either
  architecture, and images long enough to carry a Sega CD program region; any image carrying the
  `TMR SEGA` cartridge header of a Master System or Game Gear game; an SG-1000 or SC-3000 cartridge,
  which is named by the extension of the file because the image itself carries nothing to look for;
  and a Sega CD disc, as a track of 2048 or 2352 byte sectors, or as the `.cue` sheet that describes
  one. The BIOS of the drive and the save of a disc are separate files, given by the options of
  [Import options](#import-options). Of that list the Sega CD is experimental for the moment, and the
  SG-1000 and the SC-3000 have not been read from a cartridge: [Known limits](#known-limits) keeps the
  account of what has not been tested.
- A JDK, for building. Ghidra 12.1.4 targets Java 21, and the module is compiled for that release.
- BlastEm, only for live disassembly. The panel starts it as a child process, so it needs a display
  the emulator can open. Filling RAM asks one of its two debug channels, so it wants a build that
  carries `-d` and `-D`; tracing alone works without them.

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
| `ghidra_scripts/SegaFixChecksum.java` | shows the checksum the header declares and the two computed ones, writes the one you choose; it wants the 16-bit header and refuses an image without `SEGA` at `0x100` |
| `ghidra_scripts/SegaIngestAddressLog.java` | disassembles every address of a BlastEm `address.log` into the open program |

## Repository layout

```
src/main/java/sega/      loaders, headers, structures, checksum, analyzer
src/main/java/sega/live/ the live trace: emulator process, log reader, debug channels, ingest commands, plugin and panel
ghidra_scripts/          scripts that ship with the module
data/                    reserved for runtime data (Sleigh specifications, data-type archives)
src/main/help/           Ghidra help topic
scripts/                 development install
build.gradle             module build
```

## Known limits

- **The Sega CD is experimental support for the moment.** A disc, the `.cue` sheet that describes it, the
  volume of files it carries and the two address spaces are written and measured against a real disc by
  the command line; they have not had the use in a window that the cartridge loaders have had, and the
  panel of a disc runs one processor's trace at a time.
- The SG-1000 and SC-3000 support is written and compiles, and it has **not been loaded from a real
  cartridge, nor carried into a window**: the map is what the sources of an emulator say, and the machine
  is what the extension of the file says, since the image itself carries neither a header nor anything
  else that names its computer. Every import repeats this in its log. An image bigger than the `0xC000`
  byte window is placed by the Master System's mapper, which neither computer had, and the log says that
  too.
- Of a Sega CD disc the loader reads the header sector and the two programs the header places, which is
  what the boot stage itself reaches before a game is in memory, and the list of files the volume of the
  disc carries. Everything else stays on the disc until a member is imported by name or the live trace
  reaches it. A disc that also carries a Sega 32X program gets the map of the console without the 32X
  side of it, because the 32X part of such a disc is not in what the header points at.
- The volume of a disc is looked for in the sectors of 2048 bytes that a mode 1 track gives: a disc whose
  data is framed another way has no descriptor to find, and then the import says its files cannot be
  listed and goes on exactly as it did before. A volume that carries a supplementary descriptor and no
  primary one is reported and not walked. Files spread over more than one extent are listed and said of,
  not stitched together, and names spelled with the escapes of another standard — Joliet — are listed as
  they read.
- A member of a volume is read up to 1 MiB, and where its address puts it is the importer's business: the
  disc says nothing about it, and every log line about a member repeats that.
- Of a `.cue` sheet the loader reads the one track that carries a program: whichever dump holds
  `SEGADISCSYSTEM`, its own file or a file the whole disc shares, looked for next to the sheet. An audio
  track carries nothing a processor runs, a dump of a mode other than `MODE1` has no program area in it,
  and a `MOTOROLA` file is printed hexadecimal rather than stored bytes, so it cannot be read one sector
  at a time. Neither mode 2 nor CD-XA framing is recognized.
- The live trace of a disc is one processor's at a time: the panel follows the log written by the core the
  open program is the view of, so both sides of one disc mean one session each.
- Sega CD support in the live panel is experimental, and it does not run a disc whose `.cue` hands it over
  several files: the panel leaves that sheet alone. Convert the disc to a single `.iso` of its data track,
  import the `.iso` and start the session from it, or take a trace of the split disc made by a run
  elsewhere through `Ingest log…`.
- Master System and Game Gear tracing is impossible rather than unfinished: BlastEm logs no addresses
  for its Z80. Use `SegaIngestAddressLog` and the analyzers on those images, and play with the
  emulator as usual.
- On those two machines, only the first three 16 KiB pages of a cartridge are visible at a time,
  because the Z80 address space is 64 KiB and the rest arrives as overlays of the window at `0x8000`.
  Code in a page you have not selected is not reachable by the analyzers.
- Live disassembly covers the 68000 only, and covers it one translated block at a time: what BlastEm
  reports is the first address of each block, so an instruction the emulator never started a block
  with is not asked for.
- Code that runs from work RAM is reported but not disassembled until the emulator's RAM is in the
  program, because Ghidra needs bytes to disassemble.
  [Filling RAM from the emulator](#filling-ram-from-the-emulator) brings those bytes over, one window at a
  time and only while the machine stands in its debugger; a window of more than 64 KiB gives up the span
  the trace reached rather than the whole of itself, and what the machine never ran there stays unknown.
  The two channels are measured by the command line and answer with the same bytes; the `Memory` row and
  the `Fill RAM…` button of the panel have not been used in a window yet.
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
- A loader for the Master System and Game Gear: the `TMR SEGA` header, the paged cartridge windows, the
  mapper registers, the console ports, and the checksum rules those cartridges use.
- A loader for the SG-1000 and SC-3000, marked as needing testing: the cartridge mirrored over the window
  the console decodes, the 8 KiB of system RAM echoed over its own top, and the ports of each machine as
  the emulator gives them their ranges.
- Loaders for the two processors of a Sega CD disc: the disc and its sheet read for the programs the
  header declares, the address space of each processor as the ASIC shows it, the gate array, the sound
  memory and the battery RAM named, and the entries of the boot stage labelled.
- The volume of files a disc carries is read as well: its descriptors are found, its directories walked,
  and its files written into the log of every Sega CD import, so what is on the disc is known without
  mounting it. A loader imports one of those files as a program of its own, with the map of the console
  about it and the memory windows cut around it.
- The `BlastEm Live` plugin, the log reader and the batched ingest commands behind it, and
  `SegaIngestAddressLog` for working offline.
- The structures the imports lay over an image live in a category of their own, `/Sega` and
  `/Sega/Sega CD`, so a project holds one definition of each rather than one per import.
- The live panel can ask the emulator for the memory its machine runs on, by its own debugger or by the
  remote stub, and puts those bytes where the listing showed `??`.

