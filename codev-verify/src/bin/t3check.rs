//! 冒烟测试：`cargo run -p codev-verify --bin t3check -- <卡密>`
//! 只用来确认"客户端能直连 T3"，不打印任何密钥。
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let card = std::env::args().nth(1).unwrap_or_default();
    if card.is_empty() {
        eprintln!("用法: t3check <卡密>");
        std::process::exit(2);
    }
    let mut seed = [0u8; 32];
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    for (index, byte) in seed.iter_mut().enumerate() {
        *byte = ((nanos >> (index % 16 * 8)) as u8) ^ (index as u8).wrapping_mul(31);
    }
    // 起一个轮询线程，把每一段打出来（定位卡在哪一段）
    std::thread::spawn(|| {
        let mut last = "";
        for _ in 0..600 {
            let stage = codev_verify::current_stage();
            if stage != last {
                last = stage;
                eprintln!("  stage → {} ({})", codev_verify::stage_label(stage), stage);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });
    match codev_verify::verify_card(&card, &seed) {
        Ok(grant) => println!(
            "OK expires_unix={} expires_at={} notice={} license={}",
            grant.expires_unix, grant.expires_at, grant.notice, grant.license_id
        ),
        Err(error) => {
            println!("FAIL {error}");
            std::process::exit(1);
        }
    }
}
