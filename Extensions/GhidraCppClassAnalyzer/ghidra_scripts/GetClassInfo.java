// @category CppClassAnalyzer
import cppclassanalyzer.data.typeinfo.ClassTypeInfoDB;
import cppclassanalyzer.script.CppClassAnalyzerGhidraScript;

import java.math.BigInteger;

public class GetClassInfo extends CppClassAnalyzerGhidraScript {

	@Override
	protected void run() throws Exception {
		String name = askString("Class name", "Enter name of the class to print the class information of");
		Iterable<ClassTypeInfoDB> iter = currentManager.getTypes();
		boolean otherFound = false;
		ClassTypeInfoDB exactType = null;
		for (ClassTypeInfoDB type : iter) {
			String full = type.getFullName();
			if (full.equals(name)) {
				exactType = type;
				continue;
			}
			if (full.contains(name)) {
				if (!otherFound) {
					println("Other found:");
					otherFound = true;
				}
				BigInteger key = new BigInteger(String.valueOf(type.getKey()));
				println("0x" + key.toString(16) + " : " + type.getFullName());
			}
		}
		if (exactType != null) {
			println("Exact found:");
			BigInteger key = new BigInteger(String.valueOf(exactType.getKey()));
			println("0x" + key.toString(16) + ": " + exactType.getFullName());
		}
	}
}
