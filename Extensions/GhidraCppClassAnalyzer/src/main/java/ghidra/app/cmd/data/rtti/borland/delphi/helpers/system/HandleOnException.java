package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class HandleOnException extends HelperFunction {
	@Override
	public String getName() {
		return "System.@HandleOnException";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}
