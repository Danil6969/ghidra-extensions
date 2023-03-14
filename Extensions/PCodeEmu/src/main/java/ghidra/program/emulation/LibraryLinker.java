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
package ghidra.program.emulation;

import ghidra.app.plugin.core.debug.service.emulation.DebuggerPcodeMachine;
import ghidra.app.plugin.core.debug.service.modules.DefaultModuleMapProposal;
import ghidra.app.plugin.core.progmgr.ProgramManagerPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.*;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.program.emulation.relocation.RelocationResolver;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.exception.DuplicateNameException;
import org.apache.commons.lang3.ArrayUtils;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class LibraryLinker {

	private final Program currentProgram;
	private final PluginTool tool;
	private final Trace trace;
	private final DebuggerPcodeMachine emu;
	private boolean isBigEndian;
	private ProgramManagerPlugin programManager;
	private TraceModuleManager moduleManager;
	private TraceMemoryManager memoryManager;
	private PcodeExecutorState<byte []> state;
	private TracePlatform host;
	private final long alignment = 0x4000;
	private List<String> errors = new ArrayList<>();

	public LibraryLinker(Program currentProgram, PluginTool tool, Trace trace,
			DebuggerPcodeMachine emu, TraceThread thread) {
		this.currentProgram = currentProgram;
		this.tool = tool;
		this.trace = trace;
		this.emu = emu;
	}

	public void load() {
		init();
		openPrograms(currentProgram, programManager);
		addModules(trace, currentProgram, programManager);
		setImports(currentProgram, programManager, moduleManager.getAllModules(), isBigEndian);
		relocateModules(programManager, moduleManager.getAllModules());
		try (UndoableTransaction tid = UndoableTransaction.
				start(trace, "Write state")) {
			emu.writeDown(host, 0, 0);
		}
	}

	private void init() {
		isBigEndian = currentProgram.getLanguage().isBigEndian();
		programManager = PluginUtils.getOrAddPlugin(tool, ProgramManagerPlugin.class);
		moduleManager = trace.getModuleManager();
		memoryManager = trace.getMemoryManager();
		state = emu.getSharedState();
		host = trace.getPlatformManager().getHostPlatform();
	}

	private void openPrograms(Program program, ProgramManager programManager) {
		DomainFile df = program.getDomainFile();
		DomainFolder par = df.getParent();
		DomainFile[] files = par.getFiles();
		String[] libs = program.getExternalManager().getExternalLibraryNames();
		for (String lib : libs) {
			DomainFile file = findDomainFile(lib, files);
			if (file != null) {
				programManager.openProgram(file);
			}
			else {
				addError("Couldn't find library: " + lib);
			}
		}
		programManager.openProgram(program);
	}

	private DomainFile findDomainFile(String name, DomainFile[] files) {
		for (DomainFile file : files) {
			if (name.equalsIgnoreCase(file.getName())) {
				return file;
			}
		}
		return null;
	}

	private void addModules(Trace trace, Program currentProgram, ProgramManager programManager) {
		List<Program> otherPrograms = new ArrayList<>(List.of(programManager.getAllOpenPrograms()));
		otherPrograms.remove(currentProgram);
		List<Program> programs = new ArrayList<>();
		programs.add(currentProgram);
		programs.addAll(otherPrograms);
		TraceModuleManager moduleManager = trace.getModuleManager();
		for (Program program : programs) {
			String name = program.getName();
			String moduleId = "Module[" + name + "]";
			TraceModule module = null;
			try (UndoableTransaction tid = UndoableTransaction.
					start(trace, "Add modules")) {
				AddressRange range = getRange(program, moduleManager.getAllModules());
				if (range == null) {
					addError("Couldn't add module \"" + name + "\" because it has invalid range");
					continue;
				}
				module = moduleManager.addLoadedModule(moduleId, name, range, 0);
			}
			catch (DuplicateNameException e) {
				addError("Duplicate name detected: " + moduleId);
			}
			if (module == null) continue;
			if (program == currentProgram) continue;
			try (UndoableTransaction tid = UndoableTransaction.
					start(trace, "Add regions")) {
				long shift = module.getBase().getOffset() - program.getImageBase().getOffset();
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				for (MemoryBlock block : blocks) {
					Address start = block.getStart().add(shift);
					moduleId = "Module[" + start + "-" + name + ":" + block.getName() + "]";
					long blockSize = block.getSize();
					AddressRange range = new AddressRangeImpl(start, blockSize);
					try {
						memoryManager.addRegion(moduleId, Lifespan.nowOn(0), range, TraceMemoryFlag.READ,
								TraceMemoryFlag.WRITE, TraceMemoryFlag.EXECUTE);
						Memory memory = program.getMemory();
						byte[] buf = new byte[(int) blockSize];
						memory.getBytes(block.getStart(), buf);
						memoryManager.putBytes(0, start, ByteBuffer.wrap(buf));
					}
					catch (DuplicateNameException e) {
						addError("Duplicate name detected: " + moduleId);
					}
					catch (MemoryAccessException e) {
						addError("Couldn't read in: " + moduleId);
					}
				}
			}
			catch (AddressOverflowException e) {
				addError("Address overflow detected: " + moduleId);
			}
			catch (TraceOverlappedRegionException e) {
				addError("Overlap detected: " + moduleId);
			}
		}
	}

	private AddressRange getRange(Program program, Collection<? extends TraceModule> modules) {
		try {
			Address imageBase = program.getImageBase();
			long imageSize = DefaultModuleMapProposal.DefaultModuleMapEntry.computeImageSize(program);
			AddressRange range = new AddressRangeImpl(imageBase, imageSize);
			for (TraceModule conflictModule = getConflictModule(range, modules);
				 conflictModule != null; conflictModule = getConflictModule(range, modules)) {
				Address newAddress = conflictModule.getRange().getMaxAddress().add(1);
				long remainder = newAddress.getOffset() % alignment;
				if (remainder != 0) {
					newAddress = newAddress.add(alignment - remainder);
				}
				range = new AddressRangeImpl(newAddress, imageSize);
			}
			return range;
		} catch (AddressOverflowException e) {
			addError("Address overflow detected: " + program.getName());
			return null;
		}
	}

	private TraceModule getConflictModule(AddressRange range, Collection<? extends TraceModule> modules) {
		for (TraceModule module : modules) {
			if (module.getRange().intersects(range)) {
				return module;
			}
		}
		return null;
	}

	private void relocateModules(ProgramManager programManager, Collection<? extends TraceModule> modules) {
		Program[] programs = programManager.getAllOpenPrograms();
		for (TraceModule module : modules) {
			String programName = module.getName();
			Program program = findProgram(programName, programs);
			try {
				RelocationResolver.relocateAll(program, module, state);
			}
			catch (MemoryAccessException e) {
				addError("Memory access exception while relocating " + programName);
			}
		}
	}

	private void setImports(Program program, ProgramManager programManager,
			Collection<? extends TraceModule> modules, boolean isBigEndian) {
		ReferenceManager referenceManager = program.getReferenceManager();
		ReferenceIterator iter = referenceManager.getExternalReferences();
		while (iter.hasNext()) {
			Reference reference = iter.next();
			if (!(reference instanceof ExternalReference)) {
				continue;
			}
			ExternalReference externalReference = (ExternalReference) reference;
			String library = externalReference.getLibraryName();
			Program libraryProgram = findProgram(library, programManager.getAllOpenPrograms());
			if (libraryProgram == null) {
				continue;
			}
			String lab = externalReference.getLabel();
			List<Symbol> symbols = libraryProgram.getSymbolTable().getGlobalSymbols(lab);
			if (symbols.isEmpty()) {
				addError("There is no \"" + lab + "\" symbol in " + library + " library");
				continue;
			}
			if (symbols.size() > 1) {
				addError("More than one instance of \"" + lab + "\"");
				continue;
			}
			Address key = externalReference.getFromAddress();
			long shift = getShift(library, modules, programManager.getAllOpenPrograms());
			Address value = symbols.get(0).getAddress().add(shift);
			int size = value.getPointerSize();
			byte[] bytes = value.getOffsetAsBigInteger().toByteArray();
			if (!isBigEndian) {
				ArrayUtils.reverse(bytes);
			}
			state.setVar(key, size, false, bytes);
		}
	}

	private Program findProgram(String name, Program[] programs) {
		for (Program program : programs) {
			if (program.getName().equalsIgnoreCase(name)) {
				return program;
			}
		}
		return null;
	}

	private long getShift(String programName, Collection<? extends TraceModule> modules, Program[] programs) {
		for (TraceModule module : modules) {
			if (!module.getName().equalsIgnoreCase(programName)) {
				continue;
			}
			Program program = findProgram(programName, programs);
			if (program == null) {
				continue;
			}
			Address staticAddress = program.getImageBase();
			Address dynamicAddress = module.getBase();
			return dynamicAddress.getOffset() - staticAddress.getOffset();
		}
		return 0;
	}

	private void addError(String error) {
		errors.add(error);
	}

	public List<String> getErrors() {
		return errors;
	}
}
