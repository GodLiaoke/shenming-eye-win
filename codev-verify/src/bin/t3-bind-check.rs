//! 判断"这张卡在 T3 那边到底绑不绑设备"。
//!
//! 不动客户端、不动安装包 —— 只拿同一张卡，用两个不同设备指纹各登录一次，
//! 看 T3 的返回：
//!   · 两台都成功  → T3 侧**没有**设备绑定（或者换绑配额开着）→ 包不更新就拦不住
//!   · 第二台被拒  → T3 侧**有**设备绑定（提示"设备绑定不一致"之类）
//!   · 第二台成功但第一台之后失效 → 允许换绑（配额型）
//!
//! ⚠️ 会消耗这张卡的换绑次数，请用测试卡跑。
//!
//! 用法：
//!   t3-bind-check --card 24位卡密 [--dev-a 设备号A] [--dev-b 设备号B]
use std::time::Instant;

fn main() {
    let mut card = String::new();
    let mut dev_a = "BINDCHECK-DEVICE-A".to_string();
    let mut dev_b = "BINDCHECK-DEVICE-B".to_string();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--card" => {
                card = args.get(index + 1).cloned().unwrap_or_default();
                index += 2;
            }
            "--dev-a" => {
                dev_a = args.get(index + 1).cloned().unwrap_or_default();
                index += 2;
            }
            "--dev-b" => {
                dev_b = args.get(index + 1).cloned().unwrap_or_default();
                index += 2;
            }
            "--help" | "-h" => {
                println!("用法: t3-bind-check --card <卡密> [--dev-a 设备号A] [--dev-b 设备号B]");
                return;
            }
            other => {
                eprintln!("未知参数：{other}");
                std::process::exit(2);
            }
        }
    }
    if card.trim().is_empty() {
        eprintln!("缺少 --card");
        std::process::exit(2);
    }

    println!("卡密：{}****（只显示首尾，避免泄漏）", head_tail(&card));
    println!("设备A：{dev_a}");
    println!("设备B：{dev_b}");
    println!();

    let first = attempt(&card, &dev_a, "设备A");
    let second = attempt(&card, &dev_b, "设备B");
    let third = attempt(&card, &dev_a, "设备A(复查)");

    println!();
    println!("──── 判定 ────");
    match (first, second, third) {
        (true, true, true) => println!(
            "T3 侧【没有】设备绑定：两台设备都能用同一张卡。\n\
             → 不改安装包的唯一办法：去 T3 后台开启「绑定设备 / 限制设备」，把「换绑次数」设 0。"
        ),
        (true, false, _) => println!(
            "T3 侧【有】设备绑定：第二台设备被拒。\n\
             → 已经是单机绑定，不需要改任何东西。"
        ),
        (true, true, false) => println!(
            "T3 侧【允许换绑（配额型）】：设备B 成功，但设备A 复查失败（被顶掉）。\n\
             → 客户会互相踢下线；把后台「换绑次数」设 0 才会真正锁死。"
        ),
        (false, _, _) => println!(
            "设备A 第一次就没通过 —— 卡本身有问题（不存在/过期/被禁用），先解决卡，再谈绑定。"
        ),
        _ => println!("结果不稳定（网络或上游抖动），建议重跑一次。"),
    }
}

fn attempt(card: &str, device: &str, label: &str) -> bool {
    // 设备种子与客户端完全一致：sha256("codev-verify-device-v1" || device_id)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"codev-verify-device-v1");
    hasher.update(device.as_bytes());
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);

    let started = Instant::now();
    match codev_verify::verify_card(card, &seed) {
        Ok(grant) => {
            println!(
                "{label}：✅ 通过（{} ms，到期 {}）",
                started.elapsed().as_millis(),
                grant.expires_at
            );
            true
        }
        Err(error) => {
            println!(
                "{label}：❌ 拒绝（{} ms）：{error}",
                started.elapsed().as_millis()
            );
            false
        }
    }
}

fn head_tail(card: &str) -> String {
    let chars: Vec<char> = card.chars().collect();
    if chars.len() <= 6 {
        return chars.iter().collect();
    }
    format!("{}{}", chars[..3].iter().collect::<String>(), chars[chars.len() - 2..].iter().collect::<String>())
}
