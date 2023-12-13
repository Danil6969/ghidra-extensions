package ghidra.app.cmd.data.rtti.borland.delphi.helpers.sysinit;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

public class GetTLS extends HelperFunction {
	@Override
	public String getName() {
		return "SysInit.@GetTls";
	}

	@Override
	public boolean isValid(Program program, Address address) {
		return false;
	}
}
