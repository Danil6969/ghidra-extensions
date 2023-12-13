package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class HandleFinallyInternal extends HelperFunction {
	@Override
	public String getName() {
		return "System.@HandleFinallyInternal";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}
