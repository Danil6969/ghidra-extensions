package ghidra.app.cmd.data.rtti.borland.delphi.helpers;

import ghidra.program.model.address.Address;

import java.util.ArrayList;
import java.util.List;

public abstract class HelperFunction {
	public abstract String getName();
	public abstract boolean isValid();

	public Address[] getMatches() {
		List<Address> list = new ArrayList<>();
		return list.toArray(new Address[list.size()]);
	}
}
