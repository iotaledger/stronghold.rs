use criterion::{criterion_group, criterion_main, Criterion};

use store::{cache, Cache};

fn bench_compression(c: &mut Criterion) {
    let mut cache = Cache::new();

    c.bench_function("Write to cache", |b| {
        b.iter(|| {
            cache.insert(b"test", b"values", None);
        });
    });
}

fn bench_compress(c: &mut Criterion) {
    let mut cache = Cache::new();

    cache.insert(b"test".to_vec(), b"values".to_vec(), None);

    c.bench_function("Read from cache", |b| {
        b.iter(|| {
            cache.get(&b"test".to_vec());
        });
    });
}

fn bench_decompress(c: &mut Criterion) {
    cache! {
          fn fib(n: u32) -> u32 => {
           match n {
               0 => 1,
               1 => 1,
               _ => fib(n - 1) + fib(n - 2),
            }
          }
    }

    fib(20);

    c.bench_function("Read from Cached function", |b| {
        b.iter(|| {
            FIB_CACHE.lock().unwrap().get(&20);
        });
    });
}

criterion_group!(benches, bench_compression, bench_compress, bench_decompress);
criterion_main!(benches);
