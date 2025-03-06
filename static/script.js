const asmInput = document.getElementById('asm-input');
const badcharsInput = document.getElementById('badchars');
const archModeSelect = document.getElementById('arch-mode');
const opcodeOutput = document.getElementById('opcode-output');

function updateOpcodes() {
    const asm = asmInput.value;
    const archMode = archModeSelect.value;
    const badchars = badcharsInput.value.split(',').map(c => c.trim().toLowerCase()).filter(c => c);

    fetch('/convert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asm, arch_mode: archMode })
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                opcodeOutput.innerHTML = `<div class="output-line"><span class="error">${data.error}</span></div>`;
                return;
            }

            let html = '';
            data.forEach(item => {
                if (item.error) {
                    html += `
                    <div class="output-line">
                        <span class="error">${item.error}</span>
                        <span class="asm">${item.line}</span>
                    </div>`;
                } else if (item.is_label) {
                    html += `
                    <div class="output-line">
                        <span class="label">${item.line}</span>
                    </div>`;
                } else {
                    const opcodes = item.opcodes.map(opc =>
                        badchars.includes(opc) ? `<span class="highlight">${opc}</span>` : opc
                    ).join(' ');
                    const hasBadchars = item.opcodes.some(opc => badchars.includes(opc));
                    html += `
                    <div class="output-line">
                        <span class="opcodes">${opcodes}</span>
                        <span class="asm ${hasBadchars ? 'highlight' : ''}">${item.line}</span>
                    </div>`;
                }
            });
            opcodeOutput.innerHTML = html;
        })
        .catch(err => console.error(err));
}

// Debounce updates
let timeout;
function debounceUpdate() {
    clearTimeout(timeout);
    timeout = setTimeout(updateOpcodes, 300);
}

asmInput.addEventListener('input', debounceUpdate);
badcharsInput.addEventListener('input', updateOpcodes);
archModeSelect.addEventListener('change', updateOpcodes);

// Initial update
updateOpcodes();