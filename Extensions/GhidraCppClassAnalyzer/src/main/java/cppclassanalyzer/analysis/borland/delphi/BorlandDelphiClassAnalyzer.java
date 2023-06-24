package cppclassanalyzer.analysis.borland.delphi;

import cppclassanalyzer.analysis.AbstractCppClassAnalyzer;
import ghidra.app.cmd.data.rtti.ClassTypeInfo;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BorlandDelphiClassAnalyzer extends AbstractCppClassAnalyzer {

	public static final String ANALYZER_NAME = "Borland Delphi Class Analyzer";

	public BorlandDelphiClassAnalyzer() {
		super(ANALYZER_NAME);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return false;
		/* String compilerIdString = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		return compilerIdString.equals("borlanddelphi"); */ // TODO
	}

	@Override
	protected boolean hasVtt() {
		return false; // TODO?
	}

	@Override
	protected boolean analyzeVftable(ClassTypeInfo type) {
		return false; // TODO?
	}

	@Override
	protected boolean analyzeConstructor(ClassTypeInfo type) {
		return false; // TODO?
	}

	@Override
	protected void init() {
		return; // TODO?
	}

	@Override
	protected boolean isDestructor(Function function) {
		return false; // TODO?
	}
}
