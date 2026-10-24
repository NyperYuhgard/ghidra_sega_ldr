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

/**
 * Loader for the 68000 the drive's own processor is: it holds all of the ASIC's program RAM, with
 * the program the disc declares for it already in place, the word RAM through both of its windows,
 * the sound memory and the battery RAM of the disc, and the ASIC at the top of its address space.
 */
public class SegaCdSubLoader extends SegaCdLoaderBase {

	public static final String LOADER_NAME = "Sega CD Loader (Sub 68000)";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	public int getTierPriority() {
		// One disc is two programs, and the loaders are ordered by ascending priority: an import
		// that names no loader lands in the view of the processor the console runs, and the drive's
		// own has to be asked for by name.
		return 1;
	}

	@Override
	boolean isSubCpu() {
		return true;
	}
}
