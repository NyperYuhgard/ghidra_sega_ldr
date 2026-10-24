//Recalculates the Mega Drive / Genesis checksum of a loaded ROM and stores it in the header.
//@category Sega
//@keytool
//@menu

import java.nio.charset.StandardCharsets;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.mem.MemoryBlock;

import sega.Checksum;

public class SegaFixChecksum extends GhidraScript {

	@Override
	protected void run() throws Exception {
		MemoryBlock rom = currentProgram.getMemory().getBlock("ROM");
		if (rom == null || rom.getStart().getOffset() != 0) {
			println("The ROM block is missing or does not start at 0, nothing to fix.");
			return;
		}

		// An 8-bit cartridge has a ROM block at 0 as well, and no 0x18E to write to.
		byte[] signature = new byte[4];
		currentProgram.getMemory().getBytes(toAddr(0x100), signature);
		if (!new String(signature, StandardCharsets.US_ASCII).equals("SEGA")) {
			println("Nothing says SEGA at 0x100, so this is not a 16-bit cartridge; nothing to fix.");
			return;
		}

		// The cartridge sums up to the end it declares, not to the size of the file on disk.
		long declaredEnd = currentProgram.getMemory().getInt(toAddr(0x1a4)) + 1;
		long end = declaredEnd > 0 && declaredEnd <= rom.getSize() ? declaredEnd : rom.getSize();

		BinaryReader reader =
			new BinaryReader(new MemoryByteProvider(currentProgram.getMemory(), rom.getStart()),
				false);
		int sum = Checksum.segaSum(reader, end, monitor);
		int xor = Checksum.sgdkXor(reader, rom.getSize(), monitor);
		int declared = currentProgram.getMemory().getShort(toAddr(Checksum.FIELD_ADDRESS)) & 0xFFFF;

		String stored = declared == sum ? Checksum.SEGA_SUM
			: declared == xor ? Checksum.SGDK_XOR : null;
		if (stored != null) {
			println(String.format("checksum 0x%04X is already correct (%s)", declared, stored));
			return;
		}

		String message = String.format(
			"The header stores 0x%04X.%nThe ROM of 0x%X byte(s) adds up to 0x%04X and XORs to 0x%04X.%nWhich value should the header keep?",
			declared, end, sum, xor);
		String[] names = { Checksum.SEGA_SUM, Checksum.SGDK_XOR };
		int[] values = { sum, xor };
		int choiceIndex = 0;
		if (isRunningHeadless()) {
			message = message.replace("Which value should the header keep?",
				"Writing " + names[0] + ".");
		}
		else {
			List<String> choices =
				List.of(String.format("%s (0x%04X)", names[0], values[0]),
					String.format("%s (0x%04X)", names[1], values[1]));
			choiceIndex = askChoice("Sega checksum", message, choices, choices.get(0))
				.equals(choices.get(0)) ? 0 : 1;
		}
		final int picked = choiceIndex;
		println(message);

		currentProgram.withTransaction("Fix Sega checksum", () -> {
			currentProgram.getMemory().setShort(toAddr(Checksum.FIELD_ADDRESS),
				(short) values[picked]);

			for (Bookmark bookmark : currentProgram.getBookmarkManager().getBookmarks(
				toAddr(Checksum.FIELD_ADDRESS))) {
				currentProgram.getBookmarkManager().removeBookmark(bookmark);
			}

			currentProgram.getListing().setComment(toAddr(Checksum.FIELD_ADDRESS), CommentType.PRE,
				names[picked] + " of the ROM, fixed by SegaFixChecksum");
		});

		println(String.format("wrote 0x%04X at 0x%X", values[picked], Checksum.FIELD_ADDRESS));
		println("The change lives in the Ghidra program, not in the ROM file; export the block to update the cartridge.");
	}
}
