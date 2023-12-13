package exceptionanalyzer.plugin.prototype;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;
import ghidra.app.cmd.data.rtti.borland.delphi.helpers.system.HandleFinally;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.*;

public class BorlandDelphiExceptionAnalyzer extends AbstractAnalyzer {

	private static final String ANALYZER_NAME = "Borland Delphi Exceptions Analyzer (32 bit)";
	private static final String DESCRIPTION =
		"This analyzer finds and creates all of the exception handlers and their associated tables.";

	public BorlandDelphiExceptionAnalyzer() {
		super(ANALYZER_NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean canAnalyze(Program program) {
		if (!program.getLanguage().toString().startsWith("x86/little/32")) return false;
		String compilerIdString = program.getCompilerSpec().getCompilerSpecID().getIdAsString().toLowerCase();
		return compilerIdString.equals("borlanddelphi");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
		Listing listing = program.getListing();
		AddressRangeIterator ranges = set.getAddressRanges();

		while (ranges.hasNext()) {
			AddressRange range = ranges.next();
			AddressSpace space = range.getAddressSpace();
			if (space.getName().equals("EXTERNAL")) {
				continue;
			}
			Address address = range.getMinAddress();

			InstructionIterator instructions = listing.getInstructions(address, true);
			while (instructions.hasNext()) {
				Instruction instruction = instructions.next();
				createCommonFunction(program, instruction.getAddress());
			}
		}
		return true;
	}

	//private AddressRange[]

	// Checks common prologue and creates function
	private boolean createCommonFunction(Program program, Address address) {
		Listing listing = program.getListing();
		if (listing.getFunctionAt(address) != null) {
			return false;
		}
		Address currentAddress = address;
		Instruction instruction0 = listing.getInstructionAt(currentAddress);
		if (instruction0 == null) {
			return false;
		}
		if (!instruction0.toString().equals("PUSH EBP")) {
			return false;
		}

		currentAddress = currentAddress.add(instruction0.getLength());
		Instruction instruction1 = listing.getInstructionAt(currentAddress);
		if (instruction1 == null) {
			return false;
		}
		if (!instruction1.toString().equals("MOV EBP,ESP")) {
			return false;
		}
		new CreateFunctionCmd(address).applyTo(program);
		return true;
	}

	private HelperFunction[] getHelpers() {
		List<HelperFunction> list = new ArrayList<>();
		list.add(new HandleFinally());
		return list.toArray(new HelperFunction[list.size()]);
	}

	private void collectAddresses(Program program) {
		HelperFunction[] helpers = getHelpers();
		Map<String, Address> addrMap;
		for (HelperFunction helper : helpers) {
			;
		}
	}
}
