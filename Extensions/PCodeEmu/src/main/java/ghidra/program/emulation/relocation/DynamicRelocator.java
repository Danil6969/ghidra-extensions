package ghidra.program.emulation.relocation;

import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.trace.model.modules.TraceModule;

public abstract class DynamicRelocator {
	protected Program program;
	protected TraceModule module;
	protected Address staticBase;
	protected Address dynamicBase;
	protected long diff;
	protected Language language;
	protected Memory memory;
	protected boolean isBigEndian;
	protected PcodeExecutorState<byte[]> state;

	public DynamicRelocator(Program program, TraceModule module, PcodeExecutorState<byte[]> state) {
		this.program = program;
		this.module = module;
		this.state = state;
	}

	public void init() {
		staticBase = program.getImageBase();
		dynamicBase = module.getBase();
		diff = dynamicBase.getOffset() - staticBase.getOffset();
		language = state.getLanguage();
		isBigEndian = language.isBigEndian();
		memory = program.getMemory();
	}

	public abstract void relocateAll() throws MemoryAccessException;
	public abstract int getByteLength(int type);

	protected byte[] readBytes(Address address, int size) throws MemoryAccessException {
		return state.getVar(address, size, false, PcodeExecutorStatePiece.Reason.INSPECT);
	}

	protected void writeBytes(Address address, int size, byte[] buf) {
		state.setVar(address, size, false, buf);
	}
}
