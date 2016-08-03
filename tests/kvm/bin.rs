#![feature(linkage, naked_functions, asm, const_fn)]
// In this example we will construct a single CPU x86 VM which will execute
// "inb 0x01" at ring 0

extern crate kvm;
extern crate memmap;
extern crate x86;

use kvm::{Capability, Exit, IoDirection, Segment, System, Vcpu, VirtualMachine};
use memmap::{Mmap, Protection};
use std::fs::File;
use std::io::{BufRead, BufReader};
use x86::bits64::paging::*;
use x86::shared::paging::*;

#[naked]
unsafe extern "C" fn use_the_port() {
    asm!("inb $0, %al" :: "i"(0x01) :: "volatile");
}

#[test]
fn io_example() {
    let vaddr = VAddr::from_usize(&use_the_port as *const _ as _);
    println!("{} {}", pml4_index(vaddr), pdpt_index(vaddr));

    static PAGE_TABLE_P: PAddr = PAddr::from_u64(0x1000);

    // Set up a page table that identity maps the lower half of the address space
    let mut anon_mmap = Mmap::anonymous(2 * (1 << 20), Protection::ReadWrite).unwrap();
    let page_table_memory = unsafe { anon_mmap.as_mut_slice() };

    type PageTable = (PML4, [PDPT; 256]);

    let page_table: &mut PageTable = unsafe {
        ::std::mem::transmute(&mut page_table_memory[PAGE_TABLE_P.as_u64() as usize])
    };
    let (ref mut pml4, ref mut pdpts) = *page_table;
    for i in 0..256 {
        let offset = 0x2000 + 0x1000 * i;
        pml4[i] = PML4Entry::new(PAddr::from_u64(offset as _), PML4_P | PML4_RW);
        let pdpt = &mut pdpts[i];
        for j in 0..512 {
            pdpt[j] = PDPTEntry::new(PAddr::from_u64(((512 * i + j) as u64) << 30),
                                     PDPT_P | PDPT_RW | PDPT_PS);
            if i == pml4_index(vaddr) && j == pdpt_index(vaddr) {
                println!("{:?}", pml4[i].get_address());
                println!("{:?}", pdpt[j].get_address());
            }
        }
    }

    page_table_memory[0x1f0000] = 0xe4;
    page_table_memory[0x1f0001] = 0x01;

    // Initialize the KVM system
    let sys = System::initialize().unwrap();

    // Create a Virtual Machine
    let mut vm = VirtualMachine::create(&sys).unwrap();

    // Ensure that the VM supports memory backing with user memory
    assert!(vm.check_capability(Capability::UserMemory) > 0);

    // Once the memory is set we can't even call length.
    let page_table_memory_limit = page_table_memory.len() - 1;

    // Map the page table memory
    vm.set_user_memory_region(0, page_table_memory, 0).unwrap();

    // Map the process
    let f = File::open("/proc/self/maps").unwrap();
    let reader = BufReader::new(f);

    for line in reader.lines() {
        let line = line.unwrap();
        //println!("{}", line);
        let mut s = line.split(' ');
        let mut s2 = s.next().unwrap().split('-');
        let begin = usize::from_str_radix(s2.next().unwrap(), 16).unwrap();
        let end = usize::from_str_radix(s2.next().unwrap(), 16).unwrap();
        if end < 0x800000000000 {
            let perm = s.next().unwrap();
            //println!("{:#X}-{:#X} {}", begin, end, perm);
            let slice = {
                let begin_ptr: *mut u8 = begin as *const u8 as _;
                unsafe { ::std::slice::from_raw_parts_mut(begin_ptr, end - begin) }
            };
            // Make sure process doesn't overlap with page table
            assert!(begin > page_table_memory_limit);
            vm.set_user_memory_region(begin as _, slice, 0).unwrap();
        }
    }

    // Create a new VCPU
    let mut vcpu = Vcpu::create(&mut vm).unwrap();

    // Set supported CPUID (KVM fails without doing this)
    let mut cpuid = sys.get_supported_cpuid().unwrap();
    vcpu.set_cpuid2(&mut cpuid).unwrap();

    // Setup the special registers
    let mut sregs = vcpu.get_sregs().unwrap();

    // Set the code segment to have base 0, limit 4GB (flat segmentation)
    let segment_template = Segment {
        base: 0x0,
        limit: 0xffffffff,
        selector: 0,
        _type: 0,
        present: 0,
        dpl: 0,
        db: 1,
        s: 0,
        l: 0,
        g: 1,
        avl: 0,
        .. Default::default()
    };

    sregs.cs = Segment {
        selector: 0x8,
        _type: 0xb,
        present: 1,
        db: 0,
        s: 1,
        l: 1,
        .. segment_template
    };

    sregs.ss = Segment {
        .. segment_template
    };

    sregs.ds = Segment {
        .. segment_template
    };

    sregs.es = Segment {
        .. segment_template
    };

    sregs.fs = Segment {
        .. segment_template
    };

    sregs.gs = Segment {
        .. segment_template
    };

    // We don't need to populate the GDT if we have our segments setup
    // cr0 - protected mode on, paging enabled
    sregs.cr0 = 0x80050033;
    sregs.cr3 = 0x1000;
    sregs.cr4 = 0x1406b0;
    sregs.efer = 0xd01;

    // Set the special registers
    vcpu.set_sregs(&sregs).unwrap();

    let mut regs = vcpu.get_regs().unwrap();
    // set the instruction pointer to 1 MB
    //regs.rip = &use_the_port as *const _ as _;
    regs.rip = 0x1f0000;
    println!("regs.rip = {:X}", regs.rip);
    // regs.rflags = 0x2;
    regs.rflags = 0x246;
    vcpu.set_regs(&regs).unwrap();

    // Actually run the VCPU
    let run = unsafe { vcpu.run() }.unwrap();

    // Ensure that the exit reason we get back indicates that the I/O
    // instruction was executed
    assert!(run.exit_reason == Exit::Io);
    let io = unsafe { *run.io() };
    assert!(io.direction == IoDirection::In);
    assert!(io.size == 1);
    assert!(io.port == 0x1);
    unsafe {
        println!("{:#?}", *run.io());
    }
}
