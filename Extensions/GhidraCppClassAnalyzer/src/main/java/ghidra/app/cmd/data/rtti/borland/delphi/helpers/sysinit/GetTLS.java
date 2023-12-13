package ghidra.app.cmd.data.rtti.borland.delphi.helpers.sysinit;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class GetTLS extends HelperFunction {
	@Override
	public String getName() {
		return "SysInit.@GetTls";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}
