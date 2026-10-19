use arypto::ope::operations;
use criterion::{Criterion, criterion_group, criterion_main};
fn benchmark_encrypt(c: &mut Criterion) {
    let pass = String::from("test");
    let input = String::from("benches/in.txt");
    let mut group = c.benchmark_group("encrypt");

    group.sample_size(30);

    group.bench_function("full", |b| {
        b.iter(|| operations::encrypt(input.clone(), &pass.clone()));
    });

    group.finish();
}
criterion_group!(benches, benchmark_encrypt);
criterion_main!(benches);
