use arypto::key_deriv;
use criterion::{Criterion, criterion_group, criterion_main};
fn benchmark_argon2id(c: &mut Criterion) {
    let pass = String::from("testpasswordandsome randomthingwords to make it longer");
    let salt = b"afjsokdfjiagsjufdajgsagfsa54gs3h";
    c.bench_function("argon2id", |b| {
        b.iter(|| key_deriv::argon_rebuild(&pass.clone(), *salt));
    });
}
criterion_group!(benches, benchmark_argon2id);
criterion_main!(benches);
