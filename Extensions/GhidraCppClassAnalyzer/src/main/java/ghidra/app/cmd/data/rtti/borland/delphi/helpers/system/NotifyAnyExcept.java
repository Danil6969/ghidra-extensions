package ghidra.app.cmd.data.rtti.borland.delphi.helpers.system;

import ghidra.app.cmd.data.rtti.borland.delphi.helpers.HelperFunction;

public class NotifyAnyExcept extends HelperFunction {
	@Override
	public String getName() {
		return "System.NotifyAnyExcept";
	}

	@Override
	public boolean isValid() {
		return true;
	}
}
