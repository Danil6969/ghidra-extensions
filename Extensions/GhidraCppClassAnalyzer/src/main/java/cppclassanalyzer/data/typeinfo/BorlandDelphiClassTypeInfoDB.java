package cppclassanalyzer.data.typeinfo;

import cppclassanalyzer.borland.delphi.BorlandDelphiClassBuilder;
import cppclassanalyzer.data.manager.recordmanagers.ProgramRttiRecordManager;
import cppclassanalyzer.database.record.ClassTypeInfoRecord;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.cmd.data.rtti.Vtable;
import ghidra.app.cmd.data.rtti.gcc.ClassTypeInfoUtils;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.nio.ByteBuffer;
import java.util.Set;
import java.util.stream.LongStream;

public class BorlandDelphiClassTypeInfoDB extends AbstractClassTypeInfoDB {

	private final GhidraClass gc;
	private long[] baseKeys;
	private int[] baseOffsets;

	public BorlandDelphiClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfoRecord record) {
		super(worker, record);
		this.gc = ClassTypeInfoUtils.getGhidraClassFromTypeName(getProgram(), getTypeName()); //TODO?
	}

	public BorlandDelphiClassTypeInfoDB(ProgramRttiRecordManager worker, ClassTypeInfo type,
										ClassTypeInfoRecord record) {
		super(worker, type, record);
		this.gc = ClassTypeInfoUtils.getGhidraClassFromTypeName(getProgram(), getTypeName()); //TODO?
	}

	@Override
	public boolean hasParent() {
		return baseKeys.length > 0;
	}

	@Override
	public ClassTypeInfoDB[] getParentModels() {
		return LongStream.of(baseKeys)
			.mapToObj(manager::getType)
			.toArray(ClassTypeInfoDB[]::new);
	}

	@Override
	public Set<ClassTypeInfo> getVirtualParents() {
		return null; //TODO
	}

	@Override
	public Vtable findVtable(TaskMonitor monitor) throws CancelledException {
		return null; //TODO
	}

	public static long[] getBaseKeys(ClassTypeInfoRecord record) {
		ByteBuffer buf = ByteBuffer.wrap(getClassData(record));
		return ClassTypeInfoRecord.getLongArray(buf);
	}

	@Override
	protected long[] getBaseKeys() {
		return baseKeys;
	}

	@Override
	protected int[] getOffsets() {
		return baseOffsets;
	}

	@Override
	public Namespace getNamespace() {
		return gc;
	}

	@Override
	protected String getPureVirtualFunctionName() {
		return "_pure_error_";
	}

	@Override
	protected BorlandDelphiClassBuilder getClassBuilder() {
		return new BorlandDelphiClassBuilder(this);
	}

	@Override
	protected void fillModelData(ClassTypeInfoRecord record) {
		return; //TODO
	}

	@Override
	protected void fillModelData(ClassTypeInfo type, ClassTypeInfoRecord record) {
		return; //TODO
	}
}
