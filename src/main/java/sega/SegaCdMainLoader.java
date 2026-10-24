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
 * Loader for the 68000 of the console itself when a Sega CD disc is what is spinning: it is given
 * the boot ROM, the window in program RAM through which it reaches the drive's processor, the word
 * RAM of the ASIC and the peripheral registers of the Mega Drive it is wired to.
 */
public class SegaCdMainLoader extends SegaCdLoaderBase {

	public static final String LOADER_NAME = "Sega CD Loader (Main 68000)";

	@Override
	public String getName() {
		return LOADER_NAME;
	}

	@Override
	boolean isSubCpu() {
		return false;
	}
}
