window.resolve_kernel_offsets = function() {
	if (fwFromUA == "3.15") {
		kernel_offsets = {
			"_vn_lock_break_slide":       0x00242CE6, // 3.55
			"__stack_chk_guard":          0x0242AD10, // 3.55
			"kqueue_close_slide":         0,//0x0017BC22, // 3.55
			"bpf_slide":                  0x0024BDA3, // 3.55
			"jmp [rsi]":                  0x001EF468, // 3.55
			"cpu_setregs":                0x003A6E80, // 3.55
			"mov cr0, rax":               0x003A6E89, // 3.55
			"sys_setuid_patch_offset":    0x001A45C0, // 3.55
			"sys_mmap_patch_offset":      0x00349A97, // 3.55
			"vm_map_protect_patch_offset":0x003417B3, // 3.55
			"amd64_syscall_patch_offset":0x003BBBEA, // 3.55
			"sys_dynlib_dlsym_patch_offset":0x000E2DA0, // 4.05
			"syscall_11_patch1_offset":   0x00EEDA90, // 3.55
			"syscall_11_patch2_offset":   0x00EEDA98, // 3.55
			"syscall_11_patch3_offset":   0x00EEDAB8, // 3.55
		};
		kernel_patches = {
			// E8 8B EE 15 00 89 C3 85 -> B8 00 00 00 00 89 C3 85
			"sys_setuid_patch_1":         0x000000B8, // 3.55-5.05
			"sys_setuid_patch_2":         0x85C38900, // 3.55-4.05
			"sys_mmap_patch_1":           0x37B54137, // 3.55
			"sys_mmap_patch_2":           0x3145C031, // 3.55-5.05
			"vm_map_protect_patch_1":     0x9090CA39, // 3.55
			"vm_map_protect_patch_2":     0x90909090, // 3.55-5.05
			"amd64_syscall_patch_1":     0x00000FE9, // 3.55
			"amd64_syscall_patch_2":     0x528B4800, // 3.55
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "3.50" || fwFromUA == "3.51") {
		kernel_offsets = {
			"_vn_lock_break_slide":       0x00242BA6, // 3.50
			"__stack_chk_guard":          0x0242AD10, // 3.50-3.55
			"kqueue_close_slide":         0,//0x0017BC22, // 3.55
			"bpf_slide":                  0x0024BC63, // 3.50
			"jmp [rsi]":                  0x001EF328, // 3.50
			"cpu_setregs":                0x003A6A40, // 3.50
			"mov cr0, rax":               0x003A6A49, // 3.50
			"sys_setuid_patch_offset":    0x001A44A0, // 3.50
			"sys_mmap_patch_offset":      0x00349667, // 3.50
			"vm_map_protect_patch_offset":0x00341383, // 3.50
			"amd64_syscall_patch_offset":0x003BB7AA, // 3.50
			"sys_dynlib_dlsym_patch_offset":0x000E2DA0, // 4.05
			"syscall_11_patch1_offset":   0x00EEDA90, // 3.50-3.55
			"syscall_11_patch2_offset":   0x00EEDA98, // 3.50-3.55
			"syscall_11_patch3_offset":   0x00EEDAB8, // 3.50-3.55
		};
		kernel_patches = {
			// E8 8B EE 15 00 89 C3 85 -> B8 00 00 00 00 89 C3 85
			"sys_setuid_patch_1":         0x000000B8, // 3.50-5.05
			"sys_setuid_patch_2":         0x85C38900, // 3.50-3.55
			"sys_mmap_patch_1":           0x37B54137, // 3.50-3.55
			"sys_mmap_patch_2":           0x3145C031, // 3.50-5.05
			"vm_map_protect_patch_1":     0x9090CA39, // 3.50-3.55
			"vm_map_protect_patch_2":     0x90909090, // 3.50-5.05
			"amd64_syscall_patch_1":     0x00000FE9, // 3.50-3.55
			"amd64_syscall_patch_2":     0x528B4800, // 3.50-3.55
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "3.55") {
		kernel_offsets = {
			"_vn_lock_break_slide":       0x00242CE6, // 3.55
			"__stack_chk_guard":          0x0242AD10, // 3.55
			"kqueue_close_slide":         0,//0x0017BC22, // 3.55
			"bpf_slide":                  0x0024BDA3, // 3.55
			"jmp [rsi]":                  0x001EF468, // 3.55
			"cpu_setregs":                0x003A6E80, // 3.55
			"mov cr0, rax":               0x003A6E89, // 3.55
			"sys_setuid_patch_offset":    0x001A45C0, // 3.55
			"sys_mmap_patch_offset":      0x00349A97, // 3.55
			"vm_map_protect_patch_offset":0x003417B3, // 3.55
			"amd64_syscall_patch_offset":0x003BBBEA, // 3.55
			"sys_dynlib_dlsym_patch_offset":0x000E2DA0, // 4.05
			"syscall_11_patch1_offset":   0x00EEDA90, // 3.55
			"syscall_11_patch2_offset":   0x00EEDA98, // 3.55
			"syscall_11_patch3_offset":   0x00EEDAB8, // 3.55
		};
		kernel_patches = {
			// E8 8B EE 15 00 89 C3 85 -> B8 00 00 00 00 89 C3 85
			"sys_setuid_patch_1":         0x000000B8, // 3.55-5.05
			"sys_setuid_patch_2":         0x85C38900, // 3.55-4.05
			"sys_mmap_patch_1":           0x37B54137, // 3.55
			"sys_mmap_patch_2":           0x3145C031, // 3.55-5.05
			"vm_map_protect_patch_1":     0x9090CA39, // 3.55
			"vm_map_protect_patch_2":     0x90909090, // 3.55-5.05
			"amd64_syscall_patch_1":     0x00000FE9, // 3.55
			"amd64_syscall_patch_2":     0x528B4800, // 3.55
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "3.70") {
		kernel_offsets = {
			"_vn_lock_break_slide":       0x00242CE6, // 3.55
			"__stack_chk_guard":          0x0242AD10, // 3.55
			"kqueue_close_slide":         0x0017BCF2, // 3.70
			"bpf_slide":                  0x0024BE73, // 3.70
			"jmp [rsi]":                  0x001EF468, // 3.55
			"cpu_setregs":                0x003A6E80, // 3.55
			"mov cr0, rax":               0x003A6E89, // 3.55
			"sys_setuid_patch_offset":    0x001A45C0, // 3.55
			"sys_mmap_patch_offset":      0x00349A97, // 3.55
			"vm_map_protect_patch_offset":0x003417B3, // 3.55
			"amd64_syscall_patch_offset":0x003BBBEA, // 3.55
			"sys_dynlib_dlsym_patch_offset":0x000E2DA0, // 4.05
			"syscall_11_patch1_offset":   0x00EEDA90, // 3.55
			"syscall_11_patch2_offset":   0x00EEDA98, // 3.55
			"syscall_11_patch3_offset":   0x00EEDAB8, // 3.55
		};
		kernel_patches = {
			// E8 8B EE 15 00 89 C3 85 -> B8 00 00 00 00 89 C3 85
			"sys_setuid_patch_1":         0x000000B8, // 3.55-5.05
			"sys_setuid_patch_2":         0x85C38900, // 3.55-4.05
			"sys_mmap_patch_1":           0x37B54137, // 3.55
			"sys_mmap_patch_2":           0x3145C031, // 3.55-5.05
			"vm_map_protect_patch_1":     0x9090CA39, // 3.55
			"vm_map_protect_patch_2":     0x90909090, // 3.55-5.05
			"amd64_syscall_patch_1":     0x00000FE9, // 3.55
			"amd64_syscall_patch_2":     0x528B4800, // 3.55
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "4.00") {
		kernel_offsets = {
			"_vn_lock_break_slide":       0x00109E96, // 4.05
			"__stack_chk_guard":          0x024600D0, // 4.05
			"kqueue_close_slide":         0x00233930, // 4.00
			"bpf_slide":                  0x00317809, // 4.05
			"jmp [rsi]":                  0x0075373F, // 4.05
			"cpu_setregs":                0x00389330, // 4.05
			"mov cr0, rax":               0x00389339, // 4.05
			"sys_setuid_patch_offset":    0x00085BB0, // 4.05
			"sys_mmap_patch_offset":      0x0031CFDC, // 4.05
			"vm_map_protect_patch_offset":0x004423E7, // 4.05
			"amd64_syscall_patch_offset":0x000ED0BB, // 4.05
			"sys_dynlib_dlsym_patch_offset":0x000E2DA0, // 4.05
			"syscall_11_patch1_offset":   0x00F179A0, // 4.05
			"syscall_11_patch2_offset":   0x00F179A8, // 4.05
			"syscall_11_patch3_offset":   0x00F179C8, // 4.05
		};
		kernel_patches = {
			// E8 8B EE 15 00 89 C3 85 -> B8 00 00 00 00 89 C3 85
			"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
			"sys_setuid_patch_2":         0x85C38900, // 3.55-4.05
			"sys_mmap_patch_1":           0x37B74137, // 4.05
			"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
			"vm_map_protect_patch_1":     0x9090C239, // 4.05
			"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
			"amd64_syscall_patch_1":     0x00007DE9, // 4.05
			"amd64_syscall_patch_2":     0x72909000, // 4.05
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "4.05") {
		kernel_offsets = {
			"_vn_lock_break_slide":       0x00109E96, // 4.05
			"__stack_chk_guard":          0x024600D0, // 4.05
			"kqueue_close_slide":         0x00233A60, // 4.05
			"bpf_slide":                  0x00317809, // 4.05
			"jmp [rsi]":                  0x0075373F, // 4.05
			"cpu_setregs":                0x00389330, // 4.05
			"mov cr0, rax":               0x00389339, // 4.05
			"sys_setuid_patch_offset":    0x00085BB0, // 4.05
			"sys_mmap_patch_offset":      0x0031CFDC, // 4.05
			"vm_map_protect_patch_offset":0x004423E7, // 4.05
			"amd64_syscall_patch_offset":0x000ED0BB, // 4.05
			"sys_dynlib_dlsym_patch_offset":0x000E2DA0, // 4.05
			"syscall_11_patch1_offset":   0x00F179A0, // 4.05
			"syscall_11_patch2_offset":   0x00F179A8, // 4.05
			"syscall_11_patch3_offset":   0x00F179C8, // 4.05
		};
		kernel_patches = {
			// E8 8B EE 15 00 89 C3 85 -> B8 00 00 00 00 89 C3 85
			"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
			"sys_setuid_patch_2":         0x85C38900, // 3.55-4.05
			"sys_mmap_patch_1":           0x37B74137, // 4.05
			"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
			"vm_map_protect_patch_1":     0x9090C239, // 4.05
			"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
			"amd64_syscall_patch_1":     0x00007DE9, // 4.05
			"amd64_syscall_patch_2":     0x72909000, // 4.05
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "4.55") {
		kernel_offsets = {
			"__stack_chk_guard":          0x02610AD0, // 4.55
			"jmp [rsi]":                  0x0013A39F, // 4.55
			"kqueue_close_slide":         0x001E2640, // 4.55
			"bpf_slide":                  0x00167FD9, // 4.55
			"cpu_setregs":                0x00280F70, // 4.55
			"mov cr0, rax":               0x00280F79, // 4.55
			"sys_setuid_patch_offset":    0x001144E3, // 4.55
			"sys_mmap_patch_offset":      0x00141D14, // 4.55
			"vm_map_protect_patch_offset":0x00396A56, // 4.55
			"amd64_syscall_patch_offset":0x003DC621, // 4.55
			"sys_dynlib_dlsym_patch_offset":0x000690C0, // 4.55
			"syscall_11_patch1_offset":   0x0102B8A0, // 4.55
			"syscall_11_patch2_offset":   0x0102B8A8, // 4.55
			"syscall_11_patch3_offset":   0x0102B8C8, // 4.55
		};
		kernel_patches = {
			// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
			"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
			"sys_setuid_patch_2":         0xC6894100, // 4.55-4.74
			"sys_mmap_patch_1":           0x37B64137, // 4.55-4.74
			"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
			"vm_map_protect_patch_1":     0x9090EA38, // 4.55-4.74
			"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
			"amd64_syscall_patch_1":     0x909079EB, // 4.55-4.74
			"amd64_syscall_patch_2":     0x72909090, // 4.55-5.05
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "4.74") {
		kernel_offsets = {
			"jmp [rsi]":                  0x00139A2F, // 4.74
			"kqueue_close_slide":         0x001E48A0, // 4.74
			"cpu_setregs":                0x00283120, // 4.74
			"mov cr0, rax":               0x00283129, // 4.74
			"sys_setuid_patch_offset":    0x00113B73, // 4.74
			"sys_mmap_patch_offset":      0x001413A4, // 4.74
			"vm_map_protect_patch_offset":0x00397876, // 4.74
			"amd64_syscall_patch_offset":0x003DD4D1, // 4.74
			"sys_dynlib_dlsym_patch_offset":0x000686A0, // 4.74
			"syscall_11_patch1_offset":   0x010349A0, // 4.74
			"syscall_11_patch2_offset":   0x010349A8, // 4.74
			"syscall_11_patch3_offset":   0x010349C8, // 4.74
		};
		kernel_patches = {
			// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C6
			"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
			"sys_setuid_patch_2":         0xC6894100, // 4.55-4.74
			"sys_mmap_patch_1":           0x37B64137, // 4.55-4.74
			"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
			"vm_map_protect_patch_1":     0x9090EA38, // 4.55-4.74
			"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
			"amd64_syscall_patch_1":     0x909079EB, // 4.55-4.74
			"amd64_syscall_patch_2":     0x72909090, // 4.55-5.05
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "5.00" || fwFromUA == "5.01") {
		kernel_offsets = {
			"jmp [rsi]":                  0x000A617D, // 5.01
			"kqueue_close_slide":         0x0016D762, // 5.01
			"cpu_setregs":                0x00232F10, // 5.01
			"mov cr0, rax":               0x00232F19, // 5.01
			"sys_setuid_patch_offset":    0x00054A72, // 5.01-5.05
			"sys_mmap_patch_offset":      0x0013D510, // 5.01
			"vm_map_protect_patch_offset":0x001A3AF6, // 5.01
			"amd64_syscall_patch_offset":0x000004B1, // 5.01-5.05
			"sys_dynlib_dlsym_patch_offset":0x002B2350, // 5.01
			"syscall_11_patch1_offset":   0x0107C820, // 5.01-5.05
			"syscall_11_patch2_offset":   0x0107C828, // 5.01-5.05
			"syscall_11_patch3_offset":   0x0107C848, // 5.01-5.05
		};
		kernel_patches = {
			// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C4
			"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
			"sys_setuid_patch_2":         0xC4894100, // 5.05
			"sys_mmap_patch_1":           0x37B64037, // 5.05
			"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
			"vm_map_protect_patch_1":     0x9090FA38, // 5.05
			"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
			"amd64_syscall_patch_1":     0x90907DEB, // 5.05
			"amd64_syscall_patch_2":     0x72909090, // 4.55-5.05
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "5.05" && devkit == true) {
		kernel_offsets = {
			"jmp [rsi]":                  0x00019FD0, // 5.05d
			"kqueue_close_slide":         0x001D76E2, // 5.05d
			"cpu_setregs":                0x002C5660, // 5.05d
			"mov cr0, rax":               0x002C5669, // 5.05d
			"sys_setuid_patch_offset":    0x00068B32, // 5.05d
			"sys_mmap_patch_offset":      0x00197BC0, // 5.05d
			"vm_map_protect_patch_offset":0x00217AA6, // 5.05d
			"amd64_syscall_patch_offset":0x000004D3, // 5.05d
			"sys_dynlib_dlsym_patch_offset":0x00360BD0, // 5.05d
			"syscall_11_patch1_offset":   0x012AFD20, // 5.05d
			"syscall_11_patch2_offset":   0x012AFD28, // 5.05d
			"syscall_11_patch3_offset":   0x012AFD48, // 5.05d
		};
		kernel_patches = {
			// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C4
			"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
			"sys_setuid_patch_2":         0xC4894100, // 5.05
			"sys_mmap_patch_1":           0x37B64037, // 5.05
			"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
			"vm_map_protect_patch_1":     0x9090FA38, // 5.05
			"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
			"amd64_syscall_patch_1":     0x90907DEB, // 5.05
			"amd64_syscall_patch_2":     0x72909090, // 4.55-5.05
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	} else if (fwFromUA == "5.05" || fwFromUA == "5.07") {
		kernel_offsets = {
			"jmp [rsi]":                  0x00093385, // 5.05
			"kqueue_close_slide":         0x0016D872, // 5.05
			"cpu_setregs":                0x00233020, // 5.05
			"mov cr0, rax":               0x00233029, // 5.05
			"sys_setuid_patch_offset":    0x00054A72, // 5.01-5.05
			"sys_mmap_patch_offset":      0x0013D620, // 5.05
			"vm_map_protect_patch_offset":0x001A3C06, // 5.05
			"amd64_syscall_patch_offset":0x000004B1, // 5.01-5.05
			"sys_dynlib_dlsym_patch_offset":0x002B2620, // 5.05
			"syscall_11_patch1_offset":   0x0107C820, // 5.01-5.05
			"syscall_11_patch2_offset":   0x0107C828, // 5.01-5.05
			"syscall_11_patch3_offset":   0x0107C848, // 5.01-5.05
		};
		kernel_patches = {
			// E8 C8 37 13 00 41 89 C6 -> B8 00 00 00 00 41 89 C4
			"sys_setuid_patch_1":         0x000000B8, // 4.05-5.05
			"sys_setuid_patch_2":         0xC4894100, // 5.05
			"sys_mmap_patch_1":           0x37B64037, // 5.05
			"sys_mmap_patch_2":           0x3145C031, // 4.05-5.05
			"vm_map_protect_patch_1":     0x9090FA38, // 5.05
			"vm_map_protect_patch_2":     0x90909090, // 4.05-5.05
			"amd64_syscall_patch_1":     0x90907DEB, // 5.05
			"amd64_syscall_patch_2":     0x72909090, // 4.55-5.05
			"sys_dynlib_dlsym_patch_1":  0x90C3C031, // 4.05-5.05
			"sys_dynlib_dlsym_patch_2":  0x90909090, // 4.05-5.05
		};
	}
	window.kernel_offsets = kernel_offsets;
	window.kernel_patches = kernel_patches;
};