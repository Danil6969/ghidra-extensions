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
//@category Emulation

import ghidra.app.plugin.core.debug.service.breakpoint.DebuggerLogicalBreakpointServicePlugin;
import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess;
import ghidra.app.plugin.core.debug.service.tracemgr.DebuggerTraceManagerServicePlugin;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.LogicalBreakpoint;
import ghidra.framework.plugintool.PluginTool;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.emulation.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.database.time.DBTraceTimeManager;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.trace.model.time.schedule.TraceSchedule;
import ghidra.util.NumericUtilities;
import ghidra.util.database.UndoableTransaction;

import java.lang.invoke.MethodHandles;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Set;

public class Tracex86 extends GhidraScript {
	StringBuffer dumped;
	Address startAddr;
	SleighLanguage lang;

	@Override
	public void run() throws Exception {
		PluginTool tool = state.getTool();

		DebuggerEmulationServicePlugin emuService = PluginUtils.getOrAddPlugin(tool, DebuggerEmulationServicePlugin.class);
		DebuggerLogicalBreakpointServicePlugin breakpointService = PluginUtils.getOrAddPlugin(tool, DebuggerLogicalBreakpointServicePlugin.class);
		DebuggerTraceManagerServicePlugin traceManager = PluginUtils.getOrAddPlugin(tool, DebuggerTraceManagerServicePlugin.class);

		NavigableMap<Address, Set<LogicalBreakpoint>> breakpoints = breakpointService.getBreakpoints(currentProgram);
		startAddr = getStart(breakpoints);
		if (startAddr == null) {
			startAddr = currentAddress;
		}
		if (startAddr == null) {
			printerr("Failed to set start address");
			return;
		}
		String start = startAddr.getOffsetAsBigInteger().toString(16);

		if (!(currentProgram.getLanguage() instanceof SleighLanguage)) {
			printerr("Must be a sleigh language");
			return;
		}
		lang = (SleighLanguage) currentProgram.getLanguage();

		dumped = new StringBuffer();
		PcodeUseropLibrary<byte[]> lib = getLibrary();

		CompilerSpec cspec = currentProgram.getCompilerSpec();
		DBTrace trace = new DBTrace("TestTrace", cspec, this);
		emuService.setEmulatorFactory(new BytesDebuggerPcodeEmulatorFactory() {
			@Override
			public DebuggerPcodeMachine<?> create(PcodeDebuggerAccess access) {
				BytesDebuggerPcodeEmulator emu = new BytesDebuggerPcodeEmulator(access) {
					@Override
					protected PcodeUseropLibrary<byte[]> createUseropLibrary() {
						return lib;
					}
				};
				doInject(emu);
				return emu;
			}
		});
		DBTraceThreadManager threadManager = trace.getThreadManager();
		DBTraceTimeManager timeManager = trace.getTimeManager();

		TraceThread thread;
		try (UndoableTransaction tid = UndoableTransaction.
				start(trace, "Initialize test trace")) {

			thread = threadManager.createThread("Test trace", 0);
			PcodeExecutor<byte[]> exec =
					TraceSleighUtils.buildByteExecutor(trace, 0, thread, 0);
			PcodeProgram initProg = SleighProgramCompiler.compileProgram(
					lang, "test", lang.getProgramCounter().getName() + " = 0x" + start + ";",
					lib);
			exec.execute(initProg, lib);
			TraceSnapshot initial = timeManager.createSnapshot("Emulation started at " + startAddr);
			ProgramEmulationUtils.loadExecutable(initial, currentProgram);
			tid.commit();
		}

		TraceSchedule schedule = TraceSchedule.parse("0:.t0-1");

		traceManager.openTrace(trace);
		traceManager.activateThread(thread);
		traceManager.activateTime(schedule);

		emuService.backgroundEmulate(trace.getPlatformManager().getHostPlatform(), schedule);
		DebuggerPcodeMachine emu = null;
		while (emu == null) {
			if (monitor.isCancelled()) return;
			Thread.sleep(200);
			emu = emuService.getCachedEmulator(trace, schedule);
		}

		LibraryLinker linker = new LibraryLinker(currentProgram, tool, trace, emu, thread);
		linker.load();
		for (String error : linker.getErrors()) {
			printerr(error);
		}
	}

	private Address getStart(NavigableMap<Address, Set<LogicalBreakpoint>> breakpoints) {
		for (Map.Entry<Address, Set<LogicalBreakpoint>> entry : breakpoints.entrySet()) {
			for (LogicalBreakpoint breakpoint : entry.getValue()) {
				if (breakpoint.getName().equals("start")) return breakpoint.getAddress();
			}
		}
		return null;
	}

	private PcodeUseropLibrary<byte[]> getLibrary() {
		return new AnnotatedPcodeUseropLibrary<byte[]>() {
			@Override
			protected MethodHandles.Lookup getMethodLookup() {
				return MethodHandles.lookup();
			}

			@PcodeUserop
			public void hexdump(byte[] in) {
				dumped.append(NumericUtilities.convertBytesToString(in));
			}
		};
	}

	private void doInject(BytesDebuggerPcodeEmulator emu) {
		AddressSpace space = startAddr.getAddressSpace();
		emu.inject(startAddr, "hexdump(" + lang.getProgramCounter().getName() + ");");
	}
}
