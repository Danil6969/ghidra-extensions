package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class DoneExcept extends HelperFunction {
	@Override
	public String getName() {
		return "System.@DoneExcept";
	}

	@Override
	public boolean isValid(Program program, Address address) {
		return false;
	}
}
