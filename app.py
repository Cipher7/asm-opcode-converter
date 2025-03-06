from flask import Flask, request, jsonify, render_template
from keystone import *
from capstone import *

app = Flask(__name__)

# Map dropdown values to Keystone/Capstone arch/mode
ARCH_MODES = {
    "x86-32": (KS_ARCH_X86, KS_MODE_32, CS_ARCH_X86, CS_MODE_32),
    "x86-64": (KS_ARCH_X86, KS_MODE_64, CS_ARCH_X86, CS_MODE_64),
    "arm-32": (KS_ARCH_ARM, KS_MODE_ARM, CS_ARCH_ARM, CS_MODE_ARM),
    "arm-64": (KS_ARCH_ARM64, KS_MODE_64, CS_ARCH_ARM64, CS_MODE_ARM)
}

def strip_comments(line):
    """Remove assembly comments (anything after ';')."""
    return line.split(';', 1)[0].strip()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/convert', methods=['POST'])
def convert_asm():
    data = request.get_json()
    asm_code = data.get('asm', '')
    arch_mode = data.get('arch_mode', 'x86-32')

    ks_arch, ks_mode, cs_arch, cs_mode = ARCH_MODES.get(arch_mode, 
                                        (KS_ARCH_X86, KS_MODE_32, CS_ARCH_X86, CS_MODE_32))
    
    try:
        # Initialize assembler and disassembler
        ks = Ks(ks_arch, ks_mode)
        cs = Cs(cs_arch, cs_mode)
        result = []

        # Clean input and assemble
        clean_asm = '\n'.join(strip_comments(line) for line in asm_code.strip().split('\n') if strip_comments(line))
        try:
            # Assemble everything at once
            encoding, _ = ks.asm(clean_asm, as_bytes=True)
            if encoding:
                # Disassemble the raw bytes and show what instructions they represent
                for insn in cs.disasm(encoding, 0):
                    result.append({
                        "line": f"{insn.mnemonic} {insn.op_str}",
                        "opcodes": [f"0x{b:02x}" for b in insn.bytes]
                    })

        except KsError as e:
            return jsonify({"error": f"Assembly error: {str(e)}"})

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True)