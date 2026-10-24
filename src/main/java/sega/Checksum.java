/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sega;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The two conventions that fill in the checksum field of a Mega Drive header.
 * <p>
 * Sega's rule adds the big endian 16-bit words of the program and folds every carry back into the
 * running total. Homebrew assembled with SGDK instead XORs the 32-bit words of the whole image and
 * folds the result once, which is what {@code sizebnd -checksum} writes. Hacked ROMs commonly keep
 * the checksum of the original they were cut from, so matching neither rule says more about the
 * patch than about the loader.
 */
public class Checksum {

	public static final long FIELD_ADDRESS = 0x18e;

	public static final String SEGA_SUM = "Sega word sum";
	public static final String SGDK_XOR = "SGDK word XOR";

	private Checksum() {
	}

	/**
	 * Sums the 16-bit words of {@code [0, end)}, ignoring the value stored in the field itself.
	 */
	public static int segaSum(BinaryReader reader, long end, TaskMonitor monitor)
			throws IOException, CancelledException {

		monitor.initialize(end / 2);
		monitor.setMessage("Calculating checksum");

		long sum = 0;
		for (long address = 0; address + 1 < end; address += 2) {
			monitor.checkCancelled();
			monitor.setProgress(address / 2);
			reader.setPointerIndex(address);
			int word = reader.readNextUnsignedShort();
			if (address != FIELD_ADDRESS) {
				sum += word;
			}
		}
		if ((end & 1) != 0) {
			reader.setPointerIndex(end - 1);
			sum += reader.readNextUnsignedByte() << 8;
		}

		while ((sum >>> 16) != 0) {
			sum = (sum & 0xffff) + (sum >>> 16);
		}
		return (int) sum;
	}

	/**
	 * XORs the 32-bit words of {@code [0, length)} with the field zeroed, then folds the halves of
	 * the result together once.
	 */
	public static int sgdkXor(BinaryReader reader, long length, TaskMonitor monitor)
			throws IOException, CancelledException {

		long end = length & ~3L;

		monitor.initialize(end / 4);
		monitor.setMessage("Calculating checksum");

		long sum = 0;
		for (long address = 0; address < end; address += 4) {
			monitor.checkCancelled();
			monitor.setProgress(address / 4);
			reader.setPointerIndex(address);
			long word = reader.readNextUnsignedInt();
			if (address == (FIELD_ADDRESS & ~3L)) {
				// The field holds the low half of this word and must not count towards itself.
				word &= 0xffff0000L;
			}
			sum ^= word;
		}

		return (int) ((sum ^ (sum >>> 16)) & 0xffff);
	}
}
