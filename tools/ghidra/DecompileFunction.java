import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class DecompileFunction extends GhidraScript {
    private static String jsonEscape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            printerr("usage: DecompileFunction <function_address>");
            return;
        }

        Address address;
        try {
            address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[0]);
        } catch (Exception ex) {
            printerr("invalid address: " + args[0]);
            return;
        }

        FunctionManager manager = currentProgram.getFunctionManager();
        Function function = manager.getFunctionContaining(address);
        if (function == null) {
            function = manager.getFunctionAt(address);
        }
        if (function == null) {
            printerr("function not found at or containing: " + address);
            return;
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        try {
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);

            println("{");
            println("  \"function\": \"" + jsonEscape(function.getName()) + "\",");
            println("  \"entry\": \"" + jsonEscape(function.getEntryPoint().toString()) + "\",");
            println("  \"success\": " + results.decompileCompleted() + ",");
            if (!results.decompileCompleted()) {
                println("  \"error\": \"" + jsonEscape(results.getErrorMessage()) + "\"");
                println("}");
                return;
            }

            String pseudoC = results.getDecompiledFunction().getC();
            println("  \"pseudo_c\": \"" + jsonEscape(pseudoC) + "\"");
            println("}");
        } finally {
            decompiler.dispose();
        }
    }
}
