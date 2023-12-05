package exceptionanalyzer.plugin.prototype;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class BorlandDelphiExceptionAnalyzer extends AbstractAnalyzer {

	private static final String ANALYZER_NAME = "Borland Delphi Exceptions Analyzer (32 bit)";
	private static final String DESCRIPTION =
		"This analyzer finds and creates all of the exception handlers and their associated tables.";

	public BorlandDelphiExceptionAnalyzer() {
		super(ANALYZER_NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean canAnalyze(Program program) {
		String compilerIdString = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		return compilerIdString.equals("borlanddelphi");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
		return true;
	}
}
