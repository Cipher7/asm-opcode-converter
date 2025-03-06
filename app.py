from flask import Flask, request, jsonify, render_template
from keystone import *

app = Flask(__name__)

# Map dropdown values to Keystone arch/mode
ARCH_MODES = {
    "x86-32": (KS_ARCH_X86, KS_MODE_32),
    "x86-64": (KS_ARCH_X86, KS_MODE_64),
    "arm-32": (KS_ARCH_ARM, KS_MODE_ARM),
    "arm-64": (KS_ARCH_ARM64, KS_MODE_64)
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

    arch, mode = ARCH_MODES.get(arch_mode, (KS_ARCH_X86, KS_MODE_32))
    asm_lines = asm_code.strip().split('\n')

    try:
        ks = Ks(arch, mode)
        result = []

        for line in asm_lines:
            line = strip_comments(line)  # Remove comments
            if not line:
                continue
            if line.endswith(':'):
                result.append({"line": line, "opcodes": [], "is_label": True})
            else:
                try:
                    encoding, _ = ks.asm(line)
                    result.append({
                        "line": line,
                        "opcodes": [f"0x{byte:02x}" for byte in encoding]
                    })
                except KsError as e:
                    if e.errno == KS_ERR_ASM_SYMBOL_MISSING:
                        result.append({
                            "line": line,
                            "opcodes": [],
                            "error": "Unresolved symbol (e.g., jump/call to undefined label)"
                        })
                    elif e.errno == KS_ERR_ASM_MISSINGFEATURE:
                        result.append({
                            "line": line,
                            "opcodes": [],
                            "error": "Instruction not supported in this mode"
                        })
                    else:
                        result.append({
                            "line": line,
                            "opcodes": [],
                            "error": f"Assembly error: {str(e)}"
                        })

        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"})

if __name__ == '__main__':
    app.run(debug=True)