extern crate winapi;
use winapi::um::*;
use std::ffi::{CString, CStr};
use std::mem::size_of;
use winapi::shared;
use shared::minwindef::{DWORD, BOOL, HINSTANCE__};
use winnt::HANDLE;
use winapi::ctypes::c_void;

fn find_process_id_by_name(name: &str) -> Option<DWORD> {
	let name = CString::new(name).unwrap();
	let mut result = None;

	unsafe {
		let snapshot = tlhelp32::CreateToolhelp32Snapshot(tlhelp32::TH32CS_SNAPPROCESS, 0);
		
		let mut entry = tlhelp32::PROCESSENTRY32 {
			dwSize: size_of::<tlhelp32::PROCESSENTRY32>() as u32,
			cntUsage: 0,
			th32ProcessID: 0,
			th32DefaultHeapID: 0,
			th32ModuleID: 0,
			cntThreads: 0,
			th32ParentProcessID: 0,
			pcPriClassBase: 0,
			dwFlags: 0,
			szExeFile: [0; 260]
		};

		if tlhelp32::Process32First(snapshot, &mut entry as *mut tlhelp32::PROCESSENTRY32) != 0 {
			//let process_name = CStr::from_bytes_with_nul(&*(&mut entry.szExeFile[..] as *mut [i8] as *mut [u8])).unwrap();
			let process_name = CStr::from_ptr(&mut entry.szExeFile[0] as *const i8);

			if CString::from(process_name) == name {
				result = Some(entry.th32ProcessID);
			}
		}

		if result == None {
			while tlhelp32::Process32Next(snapshot, &mut entry as *mut tlhelp32::PROCESSENTRY32) != 0 {
				let process_name = CStr::from_ptr(&mut entry.szExeFile[0] as *const i8);

				if CString::from(process_name) == name {
					result = Some(entry.th32ProcessID);
					break;
				}
			}
		}

		handleapi::CloseHandle(snapshot);
	}

	result
}

fn get_module_info(process: HANDLE, module: &str) -> Option<psapi::MODULEINFO> {
	unsafe {
		let mut modules = [0 as *mut HINSTANCE__; 1024];
		let size = size_of::<[*mut HINSTANCE__; 1024]>() as DWORD;
		let mut used_size = 0 as DWORD;

		if psapi::EnumProcessModulesEx(process, &mut (modules[0]) as *mut *mut HINSTANCE__, size, &mut used_size as *mut DWORD, psapi::LIST_MODULES_ALL) != 0 {
			assert!(used_size <= size);
			let module_count = used_size as usize / size_of::<*mut HINSTANCE__>();
			let mut buf = [0i8; 128];

			for i in 0..module_count {
				if psapi::GetModuleBaseNameA(process, modules[i], &mut buf[0] as *mut i8, 128) != 0 {
					let module_name = CStr::from_ptr(&mut buf[0] as *mut i8).to_str().unwrap();
					//println!("module name = {}", module_name);

					if module_name == module {
						let mut info = psapi::MODULEINFO {
							lpBaseOfDll: 0 as *mut winapi::ctypes::c_void,
							SizeOfImage: 0,
							EntryPoint: 0 as *mut winapi::ctypes::c_void
						};

						if psapi::GetModuleInformation(process, modules[0], &mut info as *mut psapi::MODULEINFO, size_of::<psapi::MODULEINFO>() as DWORD) != 0 {
							return Some(info);
						} else {
							let err = errhandlingapi::GetLastError();
							println!("GetModuleInformation failed with error code: {}", err);
						}

						break;
					}
				} else {
					let err = errhandlingapi::GetLastError();
					println!("GetModuleBaseNameA failed with error code: {}", err);
				}
			}

		} else {
			let err = errhandlingapi::GetLastError();
			println!("EnumProcessModules failed with error code: {}", err);
		}
	}

	None
}

fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize>
{
	// let relevant_part = &data[..data.len()-pattern.len()];
	// assert!(relevant_part.len() >= pattern.len());
	assert!((data.len()-pattern.len()) >= pattern.len());

	for i in 0..(data.len() - pattern.len()) {
		if &data[i..i+pattern.len()] == pattern {
			return Some(i)
		}
	}

	None
}

fn scan_pattern(process: HANDLE, base_addr: *const c_void, size: usize, pattern: &[u8]) -> Option<usize> {
	//let mut buf = Box::<[u8]>::new_uninit_slice(size);
	let mut buf = Vec::<u8>::with_capacity(128 * 1024 * 1024);
	let mut current_addr = 0 as usize;

	let mut regions = 0;
	let mut skipped = 0;

	unsafe {
		
		while current_addr < (base_addr as usize + size) {
			let mut info = winnt::MEMORY_BASIC_INFORMATION {
				BaseAddress: 0 as *mut c_void,
				AllocationBase: 0 as *mut c_void,
				AllocationProtect: 0,
				RegionSize: 0,
				State: 0,
				Protect: 0,
				Type: 0
			};
	
			let filled = memoryapi::VirtualQueryEx(process, current_addr as *const c_void, &mut info as *mut winnt::MEMORY_BASIC_INFORMATION, size_of::<winnt::MEMORY_BASIC_INFORMATION>());
			assert_ne!(filled, 0);
			
			regions += 1;

			if (info.State & winnt::MEM_COMMIT) != 0 && (info.Protect & winnt::PAGE_GUARD) == 0 && (info.Protect & winnt::PAGE_NOACCESS) == 0 {
				//println!("yes");
				let mut bytes_read = 0 as usize;
	
				//println!("RegionSize: {}", info.RegionSize);
				assert!(buf.capacity() >= info.RegionSize);
	
				if memoryapi::ReadProcessMemory(process, info.BaseAddress, buf.as_mut_ptr() as *mut c_void, info.RegionSize, &mut bytes_read as *mut usize) == 0 {
					let err = errhandlingapi::GetLastError();
					panic!("ReadProcessMemory failed with error code: {}", err);
				}

				//println!("bytes_read {}", bytes_read);
				buf.set_len(bytes_read);

				if let Some(idx) = find_pattern(buf.as_mut(), pattern) {
					let addr = info.BaseAddress as usize + idx;
					println!("found pattern at {:#X}, total regions scanned: {}, skipped: {} (total {})", addr, (regions - skipped), skipped, regions);
					return Some(addr);
				}
			} else {
				skipped += 1;
				//println!("no");
			}

			current_addr += info.RegionSize;
		}
		

		//println!("BaseAddress {:#X}, AllocationBase {:#X}, RegionSize {:#X}", info.BaseAddress as usize, info.AllocationBase as usize, info.RegionSize);

		
	}

	println!("did not find pattern, total regions scanned: {}, skipped: {} (total {})", (regions - skipped), skipped, regions);

	None
}

fn nop_memory(process: HANDLE, addr: *mut c_void, size: usize) {
	const ASM_NOP: u8 = 0x90;
	const NOP_ARRAY_SIZE: usize = 128;
	let nop_array = [ASM_NOP; NOP_ARRAY_SIZE];
	assert!(NOP_ARRAY_SIZE >= size);

	unsafe {
		let mut old_protect = 0 as DWORD;

		if memoryapi::VirtualProtectEx(process, addr, size, winnt::PAGE_EXECUTE_READWRITE, &mut old_protect as *mut DWORD) == 0 {
			let err = errhandlingapi::GetLastError();
			panic!("VirtualAllocEx failed with error code: {}", err);
		}

		let mut bytes_written = 0 as usize;

		if memoryapi::WriteProcessMemory(process, addr, &nop_array[0] as *const u8 as *const c_void, size, &mut bytes_written as *mut usize) == 0 {
			let err = errhandlingapi::GetLastError();
			panic!("WriteProcessMemory failed with error code: {}", err);
		}

		let mut temp = 0 as DWORD; // According to the MSDN documentation the function will fail if lpflOldProtect is null

		if memoryapi::VirtualProtectEx(process, addr, size, old_protect, &mut temp as *mut DWORD) == 0 {
			let err = errhandlingapi::GetLastError();
			panic!("VirtualAllocEx failed with error code: {}", err);
		}
	}
}

fn main() {
	let process_name = "Terraria.exe";
	let process_id = find_process_id_by_name(process_name).expect(format!("did not find process with name {}", process_name).as_str());
	println!("found process id {}", process_id);
	
	let pattern = [0x80, 0xBE, 0x52, 0x01, 0x00, 0x00, 0x00];

	unsafe {
		let process = processthreadsapi::OpenProcess(winnt::PROCESS_ALL_ACCESS, false as BOOL, process_id);
		
		//println!("proc handle = {}", process_handle as u32);
		//let info = get_module_info(process, process_name).unwrap();
		//println!("lpBaseOfDll: {:#X}, SizeOfImage: {:#X}, EntryPoint: {:#X}", info.lpBaseOfDll as u64, info.SizeOfImage, info.EntryPoint as u64);

		println!("scanning...");
		//scan_pattern(process, info.lpBaseOfDll, info.SizeOfImage as usize, &pattern);
		if let Some(addr) = scan_pattern(process, 0 as *const c_void, 0x7fffffffffffffff, &pattern) {
			println!("pattern found, nopping...");
			nop_memory(process, addr as *mut c_void, pattern.len());
		} else {
			println!("pattern was not found");
		}

		handleapi::CloseHandle(process);
	}

	println!("done");
}
