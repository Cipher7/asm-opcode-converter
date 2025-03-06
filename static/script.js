let editor;
const opcodeOutput = document.getElementById('opcode-output');

document.addEventListener('DOMContentLoaded', () => {
    editor = CodeMirror(document.getElementById('editor-container'), {
        mode: 'gas',
        theme: 'monokai',
        lineNumbers: true,
        lineWrapping: false,
        tabSize: 4,
        indentUnit: 4,
        scrollbarStyle: null,
        placeholder: 'Enter ASM code...',
        viewportMargin: Infinity,
    });

    editor.on('change', debounceUpdate);

    const copyBtn = document.getElementById('copyBtn');
    if (copyBtn) {
        copyBtn.innerHTML = '<i class="fas fa-copy"></i><i class="fas fa-check"></i>';
        copyBtn.addEventListener('click', async () => {
            const code = editor.getValue();
            await navigator.clipboard.writeText(code);
            copyBtn.classList.add('copied');
            setTimeout(() => {
                copyBtn.classList.remove('copied');
            }, 2000);
        });
    }

    // Initialize controls
    const badcharsInput = document.getElementById('badchars');
    const archModeSelect = document.getElementById('arch-mode');

    if (badcharsInput && archModeSelect) {
        badcharsInput.addEventListener('input', debounceUpdate);
        archModeSelect.addEventListener('change', debounceUpdate);
        // Initial update
        updateOpcodes();
    }
});

function updateOpcodes() {
    const asm = editor.getValue();
    const archMode = document.getElementById('arch-mode').value;
    const badchars = document.getElementById('badchars').value
        .split(',')
        .map(c => c.trim().toLowerCase())
        .filter(c => c);

    // Use absolute path for API endpoint
    fetch('/api/convert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ asm, arch_mode: archMode })
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                opcodeOutput.innerHTML = `<div class="output-line"><span class="error">${data.error}</span></div>`;
                updateBadCharCount(0);
                return;
            }

            let totalOccurrences = 0;
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
                    // Count occurrences for this line
                    item.opcodes.forEach(opc => {
                        if (badchars.includes(opc)) totalOccurrences++;
                    });

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
            updateBadCharCount(totalOccurrences);
        })
        .catch(err => console.error(err));
}

function updateBadCharCount(count) {
    const badcharsCount = document.getElementById('badchars-count');
    badcharsCount.textContent = count > 0 ? `${count} match${count > 1 ? 'es' : ''}` : '';
    badcharsCount.classList.toggle('visible', count > 0);
}

// Debounce updates
let timeout;
function debounceUpdate() {
    clearTimeout(timeout);
    timeout = setTimeout(updateOpcodes, 300);
}