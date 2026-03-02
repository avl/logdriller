use std::fmt::{Display, Formatter};
use rand::rngs::SmallRng;
use rand::RngExt;
use std::sync::OnceLock;
use divan::Bencher;


fn main() {
    // Run registered benchmarks.
    divan::main();
}

static CELL: OnceLock<Vec<String>> = OnceLock::new();


fn get_text() -> &'static [String] {
    CELL.get_or_init(|| {
        use rand::SeedableRng;
        let mut rng = SmallRng::seed_from_u64(42);
        let mut strings = vec![];
        for x in 0..10000 {
            let mut temp = String::new();
            for j in 0..10 {
                temp.push(('A' as u8 + rng.random_range(0..20)) as char);
                temp += &rng.random_range(0..1000).to_string();
                temp.push(('A' as u8 + rng.random_range(0..20)) as char);
            }
            strings.push(temp);
        }
        strings
    })
}

const FINGERPRINTS: usize = 100;

fn numeric_needles() -> Needles {
    let mut needles = Vec::new();
    for i in 0..FINGERPRINTS {
        needles.push(format!("{i}{i}"));
    }
    Needles {
        name: "numeric".to_string(),
        needles
    }
}
fn common_prefix_needles() -> Needles {
    let mut needles = Vec::new();
    for i in 0..FINGERPRINTS {
        needles.push(format!("0000{i}{i}"));
    }
    Needles {
        name: "common prefix".to_string(),
        needles
    }
}


struct Needles {
    pub name: String,
    pub needles: Vec<String>,
}

impl Display for Needles {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

// Register a `fibonacci` function and benchmark it over multiple cases.
#[divan::bench(args = [numeric_needles(), common_prefix_needles()])]
fn trie_search(bencher: Bencher, needles: &Needles)  {
    let mut temp = get_text();
    let mut trie = logdriller::trie::Trie::new();


    for (i, needle) in needles.needles.iter().enumerate() {
        trie.push_exact(&needle, i);
    }

    bencher.bench_local(move||{
        let mut hits = 0;
        for line in temp {
            trie.search_fn_fast(line, |hit| {hits += 1;}, 1000000);
        }
    });

}

// Register a `fibonacci` function and benchmark it over multiple cases.
#[divan::bench(args = [numeric_needles(), common_prefix_needles()])]
fn naive_search(bencher: Bencher, needles: &Needles)  {
    let mut temp = get_text();


    bencher.bench_local(move||{
        let mut hits = 0;
        for line in temp {
            for needle in &needles.needles {
                let mut index = 0;
                if let Some(found) = line[index..].find(needle.as_str()) {
                    index += found + 1;
                    hits += 1;
                }
            }

        }
        //println!("naive hits: {hits} in {}", temp.len());
    });

}
