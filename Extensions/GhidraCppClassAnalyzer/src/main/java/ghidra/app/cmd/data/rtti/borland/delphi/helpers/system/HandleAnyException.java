package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class HandleAnyException extends HelperFunction {
	@Override
	public String getName() {
		return "System.@HandleAnyException";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}
