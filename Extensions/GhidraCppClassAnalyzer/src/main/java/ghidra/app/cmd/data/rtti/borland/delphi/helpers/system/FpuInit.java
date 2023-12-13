package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class FpuInit extends HelperFunction {
	@Override
	public String getName() {
		return "System.@FpuInit";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}
