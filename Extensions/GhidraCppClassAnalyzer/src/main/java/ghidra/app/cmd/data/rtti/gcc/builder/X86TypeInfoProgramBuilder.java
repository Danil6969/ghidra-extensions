package ghidra.app.cmd.data.rtti.gcc.builder;

import java.util.Map;

public class X86TypeInfoProgramBuilder extends AbstractTypeInfoProgramBuilder {
	private static final Map<Long, String> typeMap = Map.ofEntries(
		getEntry(0x0011e2e0L, "b001120000000000e0301100000000000000000002000000f0eb1100000000000200000000000000a0e31100000000000200000000000000"),
		getEntry(0x0011e318L, "b0011200000000001031110000000000010000000200000068e3110000000000020000000000000050e31100000000000210000000000000"),
		getEntry(0x0011e350L, "5801120000000000303111000000000090e3110000000000"),
		getEntry(0x0011e368L, "b0011200000000005031110000000000000000000100000090e311000000000003e8ffffffffffff"),
		getEntry(0x0011e390L, "98001200000000007031110000000000"),
		getEntry(0x0011e3a0L, "98001200000000009031110000000000"),
		getEntry(0x0011e3b0L, "b00112000000000050321100000000000000000002000000f0eb1100000000000200000000000000a0e31100000000000200000000000000"),
		getEntry(0x0011e3e8L, "b0011200000000006832110000000000020000000200000048e4110000000000020000000000000020e41100000000000210000000000000"),
		getEntry(0x0011e420L, "b0011200000000007832110000000000000000000100000070e411000000000003e8ffffffffffff"),
		getEntry(0x0011e448L, "b0011200000000008832110000000000000000000100000070e411000000000003e8ffffffffffff"),
		getEntry(0x0011e470L, "98001200000000009832110000000000"),
		getEntry(0x0011e498L, "5801120000000000d032110000000000f0eb110000000000"),
		getEntry(0x0011e4b0L, "7801120000000000ec32110000000000"),
		getEntry(0x0011e4c0L, "50011200000000000033110000000000000000000000000008e511000000000068e3110000000000"),
		getEntry(0x0011e4e8L, "98011200000000003033110000000000"),
		getEntry(0x0011e4f8L, "30001200000000004d33110000000000"),
		getEntry(0x0011e508L, "78011200000000005133110000000000"),
		getEntry(0x0011e578L, "b0011200000000004035110000000000000000000400000060e7110000000000020000000000000030e7110000000000020000000000000040e7110000000000020000000000000050e71100000000000200000000000000"),
		getEntry(0x0011e5d0L, "58011200000000001035110000000000f0eb110000000000"),
		getEntry(0x0011e5e8L, "b0011200000000008035110000000000000000000400000060e711000000000003e8ffffffffffff30e711000000000003e0ffffffffffff40e711000000000003d8ffffffffffff50e711000000000003d0ffffffffffff"),
		getEntry(0x0011e640L, "b001120000000000c035110000000000000000000400000020e711000000000003e0ffffffffffff10e711000000000003d8ffffffffffff00e711000000000003d0fffffffffffff0e611000000000003c8ffffffffffff"),
		getEntry(0x0011e698L, "b0011200000000000036110000000000000000000400000020e7110000000000020000000000000010e7110000000000020800000000000000e71100000000000210000000000000f0e61100000000000218000000000000"),
		getEntry(0x0011e6f0L, "98001200000000004036110000000000"),
		getEntry(0x0011e700L, "98001200000000008036110000000000"),
		getEntry(0x0011e710L, "9800120000000000c036110000000000"),
		getEntry(0x0011e720L, "98001200000000000037110000000000"),
		getEntry(0x0011e730L, "98001200000000004037110000000000"),
		getEntry(0x0011e740L, "98001200000000008037110000000000"),
		getEntry(0x0011e750L, "9800120000000000c037110000000000"),
		getEntry(0x0011e760L, "98001200000000000038110000000000"),
		getEntry(0x0011e770L, "b001120000000000f0391100000000000000000002000000f0eb1100000000000200000000000000a0e31100000000000200000000000000"),
		getEntry(0x0011e7a8L, "b001120000000000103a1100000000000000000004000000c0e8110000000000020000000000000088e8110000000000021000000000000078e8110000000000022000000000000058e91100000000000230000000000000"),
		getEntry(0x0011e800L, "b001120000000000303a110000000000020000000600000030e911000000000003e0ffffffffffff58e911000000000003d8ffffffffffff88e8110000000000020000000000000008e911000000000003d0ffffffffffffc0e8110000000000021000000000000078e81100000000000220000000000000"),
		getEntry(0x0011e878L, "9800120000000000503a110000000000"),
		getEntry(0x0011e888L, "b001120000000000703a1100000000000000000001000000b0e811000000000003e8ffffffffffff"),
		getEntry(0x0011e8b0L, "9800120000000000903a110000000000"),
		getEntry(0x0011e8c0L, "9800120000000000b03a110000000000"),
		getEntry(0x0011e8d0L, "b001120000000000d03a110000000000020000000200000030e9110000000000020000000000000008e91100000000000210000000000000"),
		getEntry(0x0011e908L, "b001120000000000f03a110000000000000000000100000058e911000000000003e8ffffffffffff"),
		getEntry(0x0011e930L, "b001120000000000103b110000000000000000000100000058e911000000000003e8ffffffffffff"),
		getEntry(0x0011e958L, "9800120000000000303b110000000000"),
		getEntry(0x0011e968L, "b001120000000000903b1100000000000000000002000000f0eb1100000000000200000000000000a0e31100000000000200000000000000"),
		getEntry(0x0011e9a0L, "b001120000000000b03b110000000000000000000100000010ea11000000000001e8ffffffffffff"),
		getEntry(0x0011e9c8L, "b001120000000000d03b110000000000000000000200000048ea11000000000003e8ffffffffffff00ea11000000000003e0ffffffffffff"),
		getEntry(0x0011ea00L, "9800120000000000f03b110000000000"),
		getEntry(0x0011ea10L, "b001120000000000103c110000000000000000000200000048ea110000000000020000000000000000ea1100000000000200000000000000"),
		getEntry(0x0011ea48L, "9800120000000000303c110000000000"),
		getEntry(0x0011ea58L, "b001120000000000403d1100000000000000000002000000f0eb1100000000000200000000000000a0e31100000000000200000000000000"),
		getEntry(0x0011ea90L, "b001120000000000603d1100000000000100000002000000e0ea1100000000000200000000000000c8ea1100000000000210000000000000"),
		getEntry(0x0011eac8L, "5801120000000000803d11000000000008eb110000000000"),
		getEntry(0x0011eae0L, "b001120000000000a03d110000000000000000000100000008eb11000000000003e8ffffffffffff"),
		getEntry(0x0011eb08L, "9800120000000000c03d110000000000"),
		getEntry(0x0011eb18L, "b001120000000000a03e1100000000000000000002000000f0eb1100000000000200000000000000a0e31100000000000200000000000000"),
		getEntry(0x0011eb50L, "5801120000000000d03e11000000000090eb110000000000"),
		getEntry(0x0011eb68L, "b001120000000000f03e110000000000000000000100000090eb11000000000003e8ffffffffffff"),
		getEntry(0x0011eb90L, "b001120000000000103f1100000000000000000001000000b8eb11000000000003e8ffffffffffff"),
		getEntry(0x0011ebb8L, "9800120000000000303f110000000000"),
		getEntry(0x0011ebf0L, "9800120000000000d83f110000000000"),
		getEntry(0x0011ec30L, "58011200000000004040110000000000f0eb110000000000"),
		getEntry(0x0011ec48L, "b00112000000000060401100000000000100000002000000e0ec11000000000003e8ffffffffffffb8ec11000000000003e0ffffffffffff"),
		getEntry(0x0011ec80L, "b00112000000000080401100000000000100000002000000e0ec1100000000000200000000000000b8ec1100000000000210000000000000"),
		getEntry(0x0011ecb8L, "b001120000000000a040110000000000000000000100000090ed11000000000003e8ffffffffffff"),
		getEntry(0x0011ece0L, "5801120000000000c04011000000000090ed110000000000"),
		getEntry(0x0011ecf8L, "b001120000000000e040110000000000020000000200000058ed110000000000020000000000000030ed1100000000000210000000000000"),
		getEntry(0x0011ed30L, "b0011200000000000041110000000000000000000100000080ed11000000000003e8ffffffffffff"),
		getEntry(0x0011ed58L, "b0011200000000002041110000000000000000000100000080ed11000000000003e8ffffffffffff"),
		getEntry(0x0011ed80L, "98001200000000004041110000000000"),
		getEntry(0x0011ed90L, "98001200000000006041110000000000")
	);

	private static final Map<Long, String> nameMap = Map.ofEntries(
		getEntry(0x001130e0L, "N20abstract_inheritance7PrinterE"),
		getEntry(0x00113110L, "N20abstract_inheritance1IE"),
		getEntry(0x00113130L, "N20abstract_inheritance1HE"),
		getEntry(0x00113150L, "N20abstract_inheritance1GE"),
		getEntry(0x00113170L, "N20abstract_inheritance1FE"),
		getEntry(0x00113190L, "12Serializable"),
		getEntry(0x00113250L, "N7diamond7PrinterE"),
		getEntry(0x00113268L, "N7diamond1DE"),
		getEntry(0x00113278L, "N7diamond1CE"),
		getEntry(0x00113288L, "N7diamond1BE"),
		getEntry(0x00113298L, "N7diamond1AE"),
		getEntry(0x001132d0L, "N17fundamental_types4._83E"),
		getEntry(0x001132ecL, "FvvE"),
		getEntry(0x00113300L, "MN20abstract_inheritance1GEKFmvE"),
		getEntry(0x00113330L, "N17fundamental_types6NumberE"),
		getEntry(0x0011334dL, "A_i"),
		getEntry(0x00113351L, "FmvE"),
		getEntry(0x00113540L, "N10interfaces21non_virtual_functions1EE"),
		getEntry(0x00113510L, "N10interfaces4._83E"),
		getEntry(0x00113580L, "N10interfaces21non_virtual_functions1FE"),
		getEntry(0x001135c0L, "N10interfaces17virtual_functions1FE"),
		getEntry(0x00113600L, "N10interfaces17virtual_functions1EE"),
		getEntry(0x00113640L, "N10interfaces17virtual_functions1DE"),
		getEntry(0x00113680L, "N10interfaces17virtual_functions1CE"),
		getEntry(0x001136c0L, "N10interfaces17virtual_functions1BE"),
		getEntry(0x00113700L, "N10interfaces17virtual_functions1AE"),
		getEntry(0x00113740L, "N10interfaces21non_virtual_functions1BE"),
		getEntry(0x00113780L, "N10interfaces21non_virtual_functions1CE"),
		getEntry(0x001137c0L, "N10interfaces21non_virtual_functions1DE"),
		getEntry(0x00113800L, "N10interfaces21non_virtual_functions1AE"),
		getEntry(0x001139f0L, "N17large_inheritance7PrinterE"),
		getEntry(0x00113a10L, "N17large_inheritance1VE"),
		getEntry(0x00113a30L, "N17large_inheritance1WE"),
		getEntry(0x00113a50L, "N17large_inheritance1XE"),
		getEntry(0x00113a70L, "N17large_inheritance1YE"),
		getEntry(0x00113a90L, "N17large_inheritance1UE"),
		getEntry(0x00113ab0L, "N17large_inheritance1ZE"),
		getEntry(0x00113ad0L, "N17large_inheritance1DE"),
		getEntry(0x00113af0L, "N17large_inheritance1CE"),
		getEntry(0x00113b10L, "N17large_inheritance1BE"),
		getEntry(0x00113b30L, "N17large_inheritance1AE"),
		getEntry(0x00113b90L, "N10no_members7PrinterE"),
		getEntry(0x00113bb0L, "N10no_members1EE"),
		getEntry(0x00113bd0L, "N10no_members1DE"),
		getEntry(0x00113bf0L, "N10no_members1BE"),
		getEntry(0x00113c10L, "N10no_members1CE"),
		getEntry(0x00113c30L, "N10no_members1AE"),
		getEntry(0x00113d40L, "N11non_diamond7PrinterE"),
		getEntry(0x00113d60L, "N11non_diamond1DE"),
		getEntry(0x00113d80L, "N11non_diamond1CE"),
		getEntry(0x00113da0L, "N11non_diamond1BE"),
		getEntry(0x00113dc0L, "N11non_diamond1AE"),
		getEntry(0x00113ea0L, "N20no_virtual_functions7PrinterE"),
		getEntry(0x00113ed0L, "N20no_virtual_functions1DE"),
		getEntry(0x00113ef0L, "N20no_virtual_functions1CE"),
		getEntry(0x00113f10L, "N20no_virtual_functions1BE"),
		getEntry(0x00113f30L, "N20no_virtual_functions1AE"),
		getEntry(0x00113fd8L, "9Printable"),
		getEntry(0x00114040L, "N21virtual_member_access4._83E"),
		getEntry(0x00114060L, "N21virtual_member_access1HE"),
		getEntry(0x00114080L, "N21virtual_member_access1GE"),
		getEntry(0x001140a0L, "N21virtual_member_access1FE"),
		getEntry(0x001140c0L, "N21virtual_member_access1EE"),
		getEntry(0x001140e0L, "N21virtual_member_access1DE"),
		getEntry(0x00114100L, "N21virtual_member_access1CE"),
		getEntry(0x00114120L, "N21virtual_member_access1BE"),
		getEntry(0x00114140L, "N21virtual_member_access1AE"),
		getEntry(0x00114160L, "N21virtual_member_access9AbstractAE")
	);

	private static final Map<Long, String> vtableMap = Map.ofEntries(
		getEntry(0x0011c1a0L, "0000000000000000e0e2110000000000a499100000000000ce99100000000000d68f100000000000"),
		getEntry(0x0011c1c8L, "2800000000000000000000000000000018e3110000000000fa99100000000000809a100000000000f086100000000000388d100000000000c28c100000000000a48c100000000000988c100000000000f0ffffffffffffff18e31100000000006e9a100000000000ab9a1000000000006c84100000000000328d1000000000007884100000000000bc8c1000000000001e8e1000000000008689100000000000d8ffffffffffffffd8ffffffffffffff0000000000000000d8ffffffffffffff0000000000000000d8ffffffffffffffd8ffffffffffffff18e3110000000000749a100000000000b19a1000000000006c84100000000000298d1000000000007884100000000000b38c100000000000128e100000000000"),
		getEntry(0x0011c3c0L, "000000000000000050e3110000000000fe9210000000000028931000000000006c84100000000000028a10000000000078841000000000006a8a10000000000092891000000000008689100000000000"),
		getEntry(0x0011c410L, "1000000000000000000000000000000068e31100000000008292100000000000ca92100000000000f086100000000000fc861000000000008c87100000000000fc87100000000000f0fffffffffffffff0ffffffffffffff0000000000000000f0ffffffffffffff0000000000000000f0fffffffffffffff0ffffffffffffff68e3110000000000c192100000000000f5921000000000006c84100000000000f38710000000000078841000000000000b881000000000007f87100000000000"),
		getEntry(0x0011e298L, "000000000000000090e3110000000000000000000000000000000000000000006c84100000000000e0011200000000007884100000000000e0011200000000008a84100000000000"),
		getEntry(0x0011c4e0L, "0000000000000000b0e311000000000072a81000000000009ca810000000000016a1100000000000"),
		getEntry(0x0011c508L, "20000000000000000000000000000000e8e3110000000000c8a81000000000005ca9100000000000a49b100000000000b09b100000000000c89b1000000000009c9e100000000000a89e100000000000c09e1000000000001000000000000000f0ffffffffffffffe8e311000000000046a910000000000087a9100000000000209d1000000000002c9d100000000000449d100000000000000000000000000000000000000000000000000000000000e0ffffffffffffffe0ffffffffffffffe8e31100000000004fa91000000000008da9100000000000ba9a100000000000c69a100000000000de9a100000000000"),
		getEntry(0x0011c760L, "1000000000000000000000000000000020e41100000000004aa510000000000092a5100000000000209d1000000000002c9d100000000000449d100000000000000000000000000000000000000000000000000000000000f0fffffffffffffff0ffffffffffffff20e411000000000089a5100000000000bda5100000000000ba9a100000000000c69a100000000000de9a100000000000"),
		getEntry(0x0011c808L, "1000000000000000000000000000000048e41100000000008ea4100000000000d6a4100000000000a49b100000000000b09b100000000000c89b100000000000000000000000000000000000000000000000000000000000f0fffffffffffffff0ffffffffffffff48e4110000000000cda410000000000001a5100000000000ba9a100000000000c69a100000000000de9a100000000000"),
		getEntry(0x0011c8b0L, "000000000000000070e411000000000008a310000000000022a3100000000000ba9a100000000000c69a100000000000de9a100000000000"),
		getEntry(0x0011c908L, "000000000000000098e411000000000036ab10000000000060ab100000000000d2aa100000000000"),
		getEntry(0x0011c930L, "0000000000000000d0e5110000000000e2b11000000000000cb210000000000056ae100000000000"),
		getEntry(0x0011cab0L, "00000000000000000000000000000000000000000000000000000000000000000000000000000000e8e5110000000000"),
		getEntry(0x0011c958L, "18000000000000001000000000000000080000000000000000000000000000000000000000000000000000000000000040e6110000000000daac10000000000006ad10000000000032ad1000000000005ead100000000000f8fffffffffffffff8ffffffffffffff40e611000000000028ad100000000000f0fffffffffffffff0ffffffffffffff40e611000000000054ad100000000000e8ffffffffffffffe8ffffffffffffff40e611000000000080ad100000000000"),
		getEntry(0x0011ca38L, "000000000000000098e611000000000040ac10000000000062ac1000000000008aac100000000000b2ac100000000000f8ffffffffffffff98e611000000000084ac100000000000f0ffffffffffffff98e6110000000000acac100000000000e8ffffffffffffff98e6110000000000d4ac100000000000"),
		getEntry(0x0011e518L, "0000000000000000f0e6110000000000e001120000000000"),
		getEntry(0x0011e530L, "000000000000000000e7110000000000e001120000000000"),
		getEntry(0x0011e548L, "000000000000000010e7110000000000e001120000000000"),
		getEntry(0x0011e560L, "000000000000000020e7110000000000e001120000000000"),
		getEntry(0x0011cae8L, "000000000000000070e71100000000003ad810000000000064d810000000000086c6100000000000"),
		getEntry(0x0011cb10L, "48000000000000000000000000000000a8e7110000000000d6cb100000000000b0cc1000000000006ac310000000000094ba100000000000acba1000000000005ec310000000000076c310000000000088c31000000000009ac3100000000000acc3100000000000c4c31000000000003800000000000000f0ffffffffffffffa8e7110000000000a6cc100000000000f0cc10000000000081c310000000000068bc10000000000080bc100000000000e0ffffffffffffffa8e71100000000009dcc100000000000eacc10000000000093c3100000000000d0bd100000000000e8bd100000000000d0ffffffffffffffa8e711000000000094cc100000000000e4cc100000000000a5c3100000000000e8b310000000000000b4100000000000000000000000000000000000000000000000000000000000b8ffffffffffffffb8ffffffffffffffa8e711000000000088cc100000000000dbcc10000000000072bb1000000000007ebb10000000000096bb100000000000"),
		getEntry(0x0011cd48L, "6000000000000000400000000000000030000000000000005000000000000000000000000000000000e811000000000090d8100000000000c8d91000000000005cbc10000000000068bc10000000000080bc100000000000aebe100000000000babe100000000000ccbe100000000000e4be100000000000f0ffffffffffffff00e81100000000009dd9100000000000f3d9100000000000c5be10000000000094ba100000000000acba100000000000e0ffffffffffffff00e8110000000000a6d9100000000000f9d9100000000000c4bd100000000000d0bd100000000000e8bd100000000000000000000000000000000000000000000000000000000000d0ffffffffffffff1000000000000000d0ffffffffffffff00e8110000000000afd9100000000000ffd9100000000000c6b4100000000000d2b4100000000000eab4100000000000000000000000000000000000000000000000000000000000c0ffffffffffffffc0ffffffffffffff00e8110000000000bbd910000000000008da100000000000dcb3100000000000e8b310000000000000b4100000000000000000000000000000000000000000000000000000000000b0ffffffffffffffb0ffffffffffffff00e8110000000000bbd910000000000008da10000000000072bb1000000000007ebb10000000000096bb100000000000000000000000000000000000000000000000000000000000a0ffffffffffffffe0ffffffffffffffa0ffffffffffffff00e8110000000000afd9100000000000ffd910000000000046b610000000000052b61000000000006ab6100000000000"),
		getEntry(0x0011d1c0L, "000000000000000078e81100000000004acb10000000000064cb100000000000c4bd100000000000d0bd100000000000e8bd100000000000"),
		getEntry(0x0011d1f8L, "1000000000000000000000000000000088e8110000000000ceca10000000000016cb1000000000005cbc10000000000068bc10000000000080bc100000000000000000000000000000000000000000000000000000000000f0fffffffffffffff0ffffffffffffff88e81100000000000dcb10000000000041cb10000000000072bb1000000000007ebb10000000000096bb100000000000"),
		getEntry(0x0011d2a0L, "0000000000000000b0e811000000000002ca1000000000001cca10000000000072bb1000000000007ebb10000000000096bb100000000000"),
		getEntry(0x0011d2d8L, "0000000000000000c0e811000000000048ca10000000000062ca10000000000088ba10000000000094ba100000000000acba100000000000"),
		getEntry(0x0011d310L, "20000000000000000000000000000000d0e811000000000012da100000000000a6da100000000000c6b4100000000000d2b4100000000000eab4100000000000c6b7100000000000d2b7100000000000eab71000000000001000000000000000f0ffffffffffffffd0e811000000000090da100000000000d1da10000000000046b610000000000052b61000000000006ab6100000000000000000000000000000000000000000000000000000000000e0ffffffffffffffe0ffffffffffffffd0e811000000000099da100000000000d7da100000000000dcb3100000000000e8b310000000000000b4100000000000"),
		getEntry(0x0011d568L, "1000000000000000000000000000000008e91100000000000ccf10000000000054cf10000000000046b610000000000052b61000000000006ab6100000000000000000000000000000000000000000000000000000000000f0fffffffffffffff0ffffffffffffff08e91100000000004bcf1000000000007fcf100000000000dcb3100000000000e8b310000000000000b4100000000000"),
		getEntry(0x0011d610L, "1000000000000000000000000000000030e911000000000050ce10000000000098ce100000000000c6b4100000000000d2b4100000000000eab4100000000000000000000000000000000000000000000000000000000000f0fffffffffffffff0ffffffffffffff30e91100000000008fce100000000000c3ce100000000000dcb3100000000000e8b310000000000000b4100000000000"),
		getEntry(0x0011d6b8L, "000000000000000058e911000000000090cb100000000000aacb100000000000dcb3100000000000e8b310000000000000b4100000000000"),
		getEntry(0x0011d6f0L, "000000000000000068e911000000000016e310000000000040e3100000000000b0df100000000000"),
		getEntry(0x0011d718L, "00000000000000000000000000000000a0e9110000000000"),
		getEntry(0x0011d738L, "000000000000000000000000000000000000000000000000c8e9110000000000"),
		getEntry(0x0011d760L, "000000000000000058ea11000000000082f0100000000000acf010000000000048ea100000000000"),
		getEntry(0x0011d788L, "2800000000000000000000000000000090ea110000000000d8f01000000000005ef110000000000056e410000000000062e41000000000007ae4100000000000a8e6100000000000b4e6100000000000cce6100000000000f0ffffffffffffff90ea1100000000004cf110000000000089f11000000000006ce310000000000078e310000000000090e310000000000040e51000000000004ce510000000000064e5100000000000000000000000000000000000000000000000000000000000d8ffffffffffffffd8ffffffffffffff90ea11000000000052f11000000000008ff11000000000006ce310000000000078e310000000000090e3100000000000"),
		getEntry(0x0011d940L, "0000000000000000c8ea110000000000e6ed10000000000010ee1000000000006ce310000000000078e310000000000090e310000000000040e51000000000004ce510000000000064e5100000000000"),
		getEntry(0x0011d990L, "10000000000000000000000000000000e0ea1100000000006aed100000000000b2ed10000000000056e410000000000062e41000000000007ae4100000000000000000000000000000000000000000000000000000000000f0fffffffffffffff0ffffffffffffffe0ea110000000000a9ed100000000000dded1000000000006ce310000000000078e310000000000090e3100000000000"),
		getEntry(0x0011da38L, "000000000000000008eb1100000000003aec10000000000054ec1000000000006ce310000000000078e310000000000090e3100000000000"),
		getEntry(0x0011da70L, "000000000000000018eb11000000000096fc100000000000c0fc100000000000fef8100000000000"),
		getEntry(0x0011da98L, "1000000000000000000000000000000050eb110000000000"),
		getEntry(0x0011dad8L, "1c000000000000001000000000000000000000000000000068eb1100000000000c00000000000000f0ffffffffffffff68eb110000000000"),
		getEntry(0x0011db40L, "0c00000000000000000000000000000090eb110000000000"),
		getEntry(0x0011ebc8L, "0000000000000000f0eb11000000000000000000000000000000000000000000e001120000000000"),
		getEntry(0x0011db60L, "000000000000000030ec110000000000341b1100000000005e1b1100000000004c1a110000000000"),
		getEntry(0x0011db88L, "300000000000000020000000000000001000000000000000000000000000000048ec110000000000ba231100000000006024110000000000f418110000000000f0ffffffffffffff0000000000000000f0fffffffffffffff0ffffffffffffff48ec11000000000047241100000000008b2411000000000066171100000000003f1a110000000000e0ffffffffffffff0000000000000000e0ffffffffffffff1000000000000000e0ffffffffffffff48ec11000000000053241100000000009424110000000000b017110000000000331a110000000000d0fffffffffffffff0ffffffffffffffd0ffffffffffffffd0ffffffffffffff48ec11000000000047241100000000008b24110000000000bb171100000000003f1a110000000000"),
		getEntry(0x0011dd58L, "2000000000000000000000000000000080ec1100000000009e241100000000002425110000000000661711000000000052181100000000001000000000000000f0ffffffffffffff80ec11000000000012251100000000004f25110000000000b017110000000000ea18110000000000e0fffffffffffffff0ffffffffffffffe0ffffffffffffffe0ffffffffffffff80ec11000000000018251100000000005525110000000000bb17110000000000de18110000000000"),
		getEntry(0x0011deb8L, "10000000000000000000000000000000b8ec1100000000003c221100000000008422110000000000b017110000000000c417110000000000f0fffffffffffffff0fffffffffffffff0fffffffffffffff0ffffffffffffffb8ec1100000000007b22110000000000af22110000000000bb171100000000004518110000000000"),
		getEntry(0x0011df48L, "0000000000000000e0ec110000000000a621110000000000d02111000000000066171100000000007217110000000000"),
		getEntry(0x0011df78L, "20000000000000000000000000000000f8ec1100000000005e25110000000000f22511000000000090161100000000001000000000000000f0fffffffffffffff8ec110000000000dc251100000000001d261100000000005d17110000000000e0ffffffffffffffe0ffffffffffffffe0fffffffffffffff8ec110000000000e52511000000000023261100000000005117110000000000"),
		getEntry(0x0011e118L, "1000000000000000000000000000000030ed110000000000a21f110000000000ea1f1100000000000216110000000000f0fffffffffffffff0fffffffffffffff0ffffffffffffff30ed110000000000e11f11000000000015201100000000008316110000000000"),
		getEntry(0x0011e190L, "1000000000000000000000000000000058ed110000000000e61e1100000000002e1f1100000000007415110000000000f0fffffffffffffff0fffffffffffffff0ffffffffffffff58ed110000000000251f110000000000591f110000000000f515110000000000"),
		getEntry(0x0011e208L, "000000000000000080ed110000000000601d1100000000007a1d1100000000005815110000000000"),
		getEntry(0x0011ec00L, "000000000000000090ed11000000000000000000000000000000000000000000e0011200000000003c15110000000000")
	);

	private static final Map<Long, String> vttMap = Map.ofEntries(
		getEntry(0x0011c2e0L, "e0c111000000000018c311000000000088c3110000000000a8c2110000000000"),
		getEntry(0x0011c4d0L, "28c411000000000098c4110000000000"),
		getEntry(0x0011c5f8L, "20c511000000000048c6110000000000a0c6110000000000e0c611000000000038c7110000000000d0c511000000000078c5110000000000"),
		getEntry(0x0011c7f8L, "78c7110000000000d0c7110000000000"),
		getEntry(0x0011c8a0L, "20c811000000000078c8110000000000"),
		getEntry(0x0011ca10L, "90c911000000000090c9110000000000c8c9110000000000e8c911000000000008ca110000000000"),
		getEntry(0x0011cae0L, "e0ca110000000000"),
		getEntry(0x0011cc88L, "28cb110000000000c8cc11000000000020cd11000000000098cb11000000000060cc110000000000"),
		getEntry(0x0011cfa0L, "78cd11000000000010d011000000000068d011000000000068ce110000000000c0ce11000000000018cf11000000000078cf110000000000a8d011000000000000d111000000000040d111000000000098d1110000000000"),
		getEntry(0x0011d290L, "10d211000000000068d2110000000000"),
		getEntry(0x0011d400L, "28d311000000000050d4110000000000a8d4110000000000e8d411000000000040d5110000000000d8d311000000000080d3110000000000"),
		getEntry(0x0011d600L, "80d5110000000000d8d5110000000000"),
		getEntry(0x0011d6a8L, "28d611000000000080d6110000000000"),
		getEntry(0x0011d730L, "30d7110000000000"),
		getEntry(0x0011d758L, "58d7110000000000"),
		getEntry(0x0011d888L, "a0d7110000000000c0d811000000000018d911000000000060d8110000000000"),
		getEntry(0x0011da28L, "a8d911000000000000da110000000000"),
		getEntry(0x0011dab0L, "b0da110000000000d8da110000000000"),
		getEntry(0x0011db10L, "f8da11000000000010db11000000000040db110000000000"),
		getEntry(0x0011db58L, "58db110000000000"),
		getEntry(0x0011dca8L, "b0db110000000000f0db11000000000040dc11000000000088dc110000000000f0dc11000000000038dd110000000000"),
		getEntry(0x0011de10L, "70dd11000000000050de11000000000098de110000000000a8dd110000000000f0dd110000000000"),
		getEntry(0x0011df38L, "d0de11000000000018df110000000000"),
		getEntry(0x0011e010L, "90df11000000000060e011000000000098e0110000000000c8e011000000000000e1110000000000f8df110000000000c0df110000000000"),
		getEntry(0x0011e180L, "30e111000000000068e1110000000000"),
		getEntry(0x0011e1f8L, "a8e1110000000000e0e1110000000000")
	);

	private static final Map<Long, String> relocationMap = Map.ofEntries(
		getEntry(0x0011e2c0L, "__cxa_pure_virtual"),
		getEntry(0x0011e2d0L, "__cxa_pure_virtual"),
		getEntry(0x0011e2e0L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e318L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e350L, "_ZTVN10__cxxabiv120__si_class_type_infoE"),
		getEntry(0x0011e368L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e390L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e3a0L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e3b0L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e3e8L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e420L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e448L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e470L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e498L, "_ZTVN10__cxxabiv120__si_class_type_infoE"),
		getEntry(0x0011e4b0L, "_ZTVN10__cxxabiv120__function_type_infoE"),
		getEntry(0x0011e4c0L, "_ZTVN10__cxxabiv129__pointer_to_member_type_infoE"),
		getEntry(0x0011e4e8L, "_ZTVN10__cxxabiv116__enum_type_infoE"),
		getEntry(0x0011e4f8L, "_ZTVN10__cxxabiv117__array_type_infoE"),
		getEntry(0x0011e508L, "_ZTVN10__cxxabiv120__function_type_infoE"),
		getEntry(0x0011e528L, "__cxa_pure_virtual"),
		getEntry(0x0011e540L, "__cxa_pure_virtual"),
		getEntry(0x0011e558L, "__cxa_pure_virtual"),
		getEntry(0x0011e570L, "__cxa_pure_virtual"),
		getEntry(0x0011e578L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e5d0L, "_ZTVN10__cxxabiv120__si_class_type_infoE"),
		getEntry(0x0011e5e8L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e640L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e698L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e6f0L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e700L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e710L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e720L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e730L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e740L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e750L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e760L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e770L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e7a8L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e800L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e878L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e888L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e8b0L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e8c0L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e8d0L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e908L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e930L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e958L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011e968L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e9a0L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011e9c8L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ea00L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011ea10L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ea48L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011ea58L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ea90L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011eac8L, "_ZTVN10__cxxabiv120__si_class_type_infoE"),
		getEntry(0x0011eae0L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011eb08L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011eb18L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011eb50L, "_ZTVN10__cxxabiv120__si_class_type_infoE"),
		getEntry(0x0011eb68L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011eb90L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ebb8L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011ebe8L, "__cxa_pure_virtual"),
		getEntry(0x0011ebf0L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011ec20L, "__cxa_pure_virtual"),
		getEntry(0x0011ec30L, "_ZTVN10__cxxabiv120__si_class_type_infoE"),
		getEntry(0x0011ec48L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ec80L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ecb8L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ece0L, "_ZTVN10__cxxabiv120__si_class_type_infoE"),
		getEntry(0x0011ecf8L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ed30L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ed58L, "_ZTVN10__cxxabiv121__vmi_class_type_infoE"),
		getEntry(0x0011ed80L, "_ZTVN10__cxxabiv117__class_type_infoE"),
		getEntry(0x0011ed90L, "_ZTVN10__cxxabiv117__class_type_infoE")
	);

	private static final Long[] functionOffsets = new Long[]{
		0x001099a4L,
		0x001099ceL,
		0x00108fd6L,
		0x001099faL,
		0x00109a80L,
		0x001086f0L,
		0x00108d38L,
		0x00108cc2L,
		0x00108ca4L,
		0x00108c98L,
		0x00109a6eL,
		0x00109aabL,
		0x0010846cL,
		0x00108d32L,
		0x00108478L,
		0x00108cbcL,
		0x00108e1eL,
		0x00108986L,
		0x00109a74L,
		0x00109ab1L,
		0x00108d29L,
		0x00108cb3L,
		0x00108e12L,
		0x001092feL,
		0x00109328L,
		0x00108a02L,
		0x00108a6aL,
		0x00108992L,
		0x00109282L,
		0x001092caL,
		0x001086fcL,
		0x0010878cL,
		0x001087fcL,
		0x001092c1L,
		0x001092f5L,
		0x001087f3L,
		0x0010880bL,
		0x0010877fL,
		0x001201e0L,
		0x0010848aL,
		0x0010a872L,
		0x0010a89cL,
		0x0010a116L,
		0x0010a8c8L,
		0x0010a95cL,
		0x00109ba4L,
		0x00109bb0L,
		0x00109bc8L,
		0x00109e9cL,
		0x00109ea8L,
		0x00109ec0L,
		0x0010a946L,
		0x0010a987L,
		0x00109d20L,
		0x00109d2cL,
		0x00109d44L,
		0x0010a94fL,
		0x0010a98dL,
		0x00109abaL,
		0x00109ac6L,
		0x00109adeL,
		0x0010a54aL,
		0x0010a592L,
		0x0010a589L,
		0x0010a5bdL,
		0x0010a48eL,
		0x0010a4d6L,
		0x0010a4cdL,
		0x0010a501L,
		0x0010a308L,
		0x0010a322L,
		0x0010ab36L,
		0x0010ab60L,
		0x0010aad2L,
		0x0010b1e2L,
		0x0010b20cL,
		0x0010ae56L,
		0x0010acdaL,
		0x0010ad06L,
		0x0010ad32L,
		0x0010ad5eL,
		0x0010ad28L,
		0x0010ad54L,
		0x0010ad80L,
		0x0010ac40L,
		0x0010ac62L,
		0x0010ac8aL,
		0x0010acb2L,
		0x0010ac84L,
		0x0010acacL,
		0x0010acd4L,
		0x0010d83aL,
		0x0010d864L,
		0x0010c686L,
		0x0010cbd6L,
		0x0010ccb0L,
		0x0010c36aL,
		0x0010ba94L,
		0x0010baacL,
		0x0010c35eL,
		0x0010c376L,
		0x0010c388L,
		0x0010c39aL,
		0x0010c3acL,
		0x0010c3c4L,
		0x0010cca6L,
		0x0010ccf0L,
		0x0010c381L,
		0x0010bc68L,
		0x0010bc80L,
		0x0010cc9dL,
		0x0010cceaL,
		0x0010c393L,
		0x0010bdd0L,
		0x0010bde8L,
		0x0010cc94L,
		0x0010cce4L,
		0x0010c3a5L,
		0x0010b3e8L,
		0x0010b400L,
		0x0010cc88L,
		0x0010ccdbL,
		0x0010bb72L,
		0x0010bb7eL,
		0x0010bb96L,
		0x0010d890L,
		0x0010d9c8L,
		0x0010bc5cL,
		0x0010beaeL,
		0x0010bebaL,
		0x0010beccL,
		0x0010bee4L,
		0x0010d99dL,
		0x0010d9f3L,
		0x0010bec5L,
		0x0010d9a6L,
		0x0010d9f9L,
		0x0010bdc4L,
		0x0010d9afL,
		0x0010d9ffL,
		0x0010b4c6L,
		0x0010b4d2L,
		0x0010b4eaL,
		0x0010d9bbL,
		0x0010da08L,
		0x0010b3dcL,
		0x0010b646L,
		0x0010b652L,
		0x0010b66aL,
		0x0010cb4aL,
		0x0010cb64L,
		0x0010caceL,
		0x0010cb16L,
		0x0010cb0dL,
		0x0010cb41L,
		0x0010ca02L,
		0x0010ca1cL,
		0x0010ca48L,
		0x0010ca62L,
		0x0010ba88L,
		0x0010da12L,
		0x0010daa6L,
		0x0010b7c6L,
		0x0010b7d2L,
		0x0010b7eaL,
		0x0010da90L,
		0x0010dad1L,
		0x0010da99L,
		0x0010dad7L,
		0x0010cf0cL,
		0x0010cf54L,
		0x0010cf4bL,
		0x0010cf7fL,
		0x0010ce50L,
		0x0010ce98L,
		0x0010ce8fL,
		0x0010cec3L,
		0x0010cb90L,
		0x0010cbaaL,
		0x0010e316L,
		0x0010e340L,
		0x0010dfb0L,
		0x0010f082L,
		0x0010f0acL,
		0x0010ea48L,
		0x0010f0d8L,
		0x0010f15eL,
		0x0010e456L,
		0x0010e462L,
		0x0010e47aL,
		0x0010e6a8L,
		0x0010e6b4L,
		0x0010e6ccL,
		0x0010f14cL,
		0x0010f189L,
		0x0010e36cL,
		0x0010e378L,
		0x0010e390L,
		0x0010e540L,
		0x0010e54cL,
		0x0010e564L,
		0x0010f152L,
		0x0010f18fL,
		0x0010ede6L,
		0x0010ee10L,
		0x0010ed6aL,
		0x0010edb2L,
		0x0010eda9L,
		0x0010edddL,
		0x0010ec3aL,
		0x0010ec54L,
		0x0010fc96L,
		0x0010fcc0L,
		0x0010f8feL,
		0x00111b34L,
		0x00111b5eL,
		0x00111a4cL,
		0x001123baL,
		0x00112460L,
		0x001118f4L,
		0x00112447L,
		0x0011248bL,
		0x00111766L,
		0x00111a3fL,
		0x00112453L,
		0x00112494L,
		0x001117b0L,
		0x00111a33L,
		0x001117bbL,
		0x0011249eL,
		0x00112524L,
		0x00111852L,
		0x00112512L,
		0x0011254fL,
		0x001118eaL,
		0x00112518L,
		0x00112555L,
		0x001118deL,
		0x0011223cL,
		0x00112284L,
		0x001117c4L,
		0x0011227bL,
		0x001122afL,
		0x00111845L,
		0x001121a6L,
		0x001121d0L,
		0x00111772L,
		0x0011255eL,
		0x001125f2L,
		0x00111690L,
		0x001125dcL,
		0x0011261dL,
		0x0011175dL,
		0x001125e5L,
		0x00112623L,
		0x00111751L,
		0x00111fa2L,
		0x00111feaL,
		0x00111602L,
		0x00111fe1L,
		0x00112015L,
		0x00111683L,
		0x00111ee6L,
		0x00111f2eL,
		0x00111574L,
		0x00111f25L,
		0x00111f59L,
		0x001115f5L,
		0x00111d60L,
		0x00111d7aL,
		0x00111558L,
		0x0011153cL
		};

		private static final String returnString = "554889e548897df8905dc3";

		private static final String fDescriptors = "";

		public X86TypeInfoProgramBuilder() throws Exception {
			super("x86:LE:64:default", "gcc");
		}

		@Override
		protected Map<Long, String> getTypeInfoMap() {
			return typeMap;
		}

		@Override
		protected Map<Long, String> getTypeNameMap() {
			return nameMap;
		}

		@Override
		protected Map<Long, String> getVtableMap() {
			return vtableMap;
		}

		@Override
		protected Map<Long, String> getVttMap() {
			return vttMap;
		}

		@Override
		protected Map<Long, String> getRelocationMap() {
			return relocationMap;
		}

		@Override
		protected Long[] getFunctionOffsets() {
			return functionOffsets;
		}

		@Override
		protected String getReturnInstruction() {
			return returnString;
		}

		@Override
		protected String getFunctionDescriptors() {
			return fDescriptors;
		}

		@Override
		protected void setupMemory() {
			createMemory(".text", "00108360", 41777);
			createMemory(".data.rel.ro", "0011c1a0", 11264);
		}
	}
