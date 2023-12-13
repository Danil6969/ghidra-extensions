package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class DoneExcept extends HelperFunction {
	@Override
	public String getName() {
		return "System.@DoneExcept";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}
