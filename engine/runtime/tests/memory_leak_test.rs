use runtime::{
    memories::frag::{Frag, FragStrategy},
};

use std::fmt::Debug;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;


#[derive(PartialEq, Debug, Clone)]
struct TestStruct {
    id: usize,
    name: String,
}

impl Default for TestStruct {
    fn default() -> Self {
        Self {
            id: 123456789,
            name: "Some heap allocated value".to_owned(),
        }
    }
}

const NB_ALLOC: usize = 20;
// We run this the test binary with valgrind to check for potential leak
#[test]
fn test_memory_leak_without_dealloc() {
    let _ = alloc_frags(FragStrategy::Direct, NB_ALLOC);
}

#[test]
fn test_memory_no_leak() {
    alloc_frags(FragStrategy::Direct, NB_ALLOC);
}


// Test to check the dhat tool
// TODO: Not working yet
#[allow(dead_code)]
fn test_dhat() {
    
    let _profiler = dhat::Profiler::builder().testing().build();

    let stats = dhat::HeapStats::get();
    dhat::assert_eq!(stats.curr_blocks, 0);
    println!("0 - Blocks allocated: {}, bytes allocated: {}", stats.curr_blocks, stats.curr_bytes);

    const SIZE: usize = 1000;
    let b = [5i32; SIZE];

    let mut vec = Vec::with_capacity(10);
    println!("0.5 - Blocks allocated: {}, bytes allocated: {}", stats.curr_blocks, stats.curr_bytes);
    unsafe {
        for i in 0..10 {
            let ptr = libc::malloc(SIZE * 4) as *mut i32;
            std::ptr::copy(&b as *const i32, ptr, SIZE);
            let _ = std::ptr::read(ptr);
            vec.push(ptr);

            let stats = dhat::HeapStats::get();
            println!("{} - Blocks allocated: {}, bytes allocated: {}", i, stats.curr_blocks, stats.curr_bytes);

        }

        let stats = dhat::HeapStats::get();
        dhat::assert_eq!(stats.curr_blocks, 1);
        println!("final - Blocks allocated: {}, bytes allocated: {}", stats.curr_blocks, stats.curr_bytes);
        dhat::assert_eq!(stats.curr_blocks, 0);

        // libc::free(ptr);
        // let stats = dhat::HeapStats::get();
        // dhat::assert_eq!(stats.curr_blocks, 0);
    }
}


// Goal
fn alloc_frags(strat: FragStrategy, nb_alloc: usize) -> Vec<Frag<TestStruct>> {
    let mut v = vec![];
    for _ in 0..nb_alloc {
        let frags = Frag::<TestStruct>::alloc(strat, TestStruct::default(), TestStruct::default());
        assert!(frags.is_ok());
        let (f1, f2) = frags.unwrap();
        v.push(f1);
        v.push(f2);
    }
    v
}
