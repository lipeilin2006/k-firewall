//! 运行时规则持久化（SQLite）。
//!
//! 持久化 daemon 运行期间通过 API/CLI 增删、重启后需要保留的数据：
//! - `suricata_rules`：运行时增删的 Suricata 规则（重启后恢复并重同步 eBPF 预过滤表；
//!   id 由 SQLite AUTOINCREMENT 分配，重启后 DELETE 仍按 id 精确命中）。
//! - `blocklist`：运行时封禁记录（API / Suricata 自动封禁），重启后恢复并重同步内核
//!   BLOCKED map，避免重启导致已封禁 IP 自动解封。

use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use rusqlite::{Connection, OptionalExtension as _, params};

/// SQLite 持久化句柄（持路径；每次操作打开连接，避免跨任务共享连接）。
#[derive(Debug, Clone)]
pub struct Persist {
    path: PathBuf,
}

/// 运行时 Suricata 规则行（`suricata_rules`）。
#[derive(Debug, Clone)]
pub struct SuricataRuleRow {
    pub id: Option<i64>,
    /// 原始 Suricata 规则文本。
    pub text: String,
    /// 是否启用（0/1）。
    pub enabled: bool,
}

/// 运行时封禁记录行（`blocklist`）。
#[derive(Debug, Clone)]
pub struct BlocklistRow {
    pub ip: IpAddr,
    pub reason: String,
    /// 添加时刻（unix 秒）。
    pub added_unix: u64,
    /// 过期时刻（unix 秒）；`None` 表示永久封禁。
    pub expire_unix: Option<u64>,
}

/// 运行时 QoS 分类行（`qos_classes`）。
#[derive(Debug, Clone)]
pub struct QosClassRow {
    pub id: Option<i64>,
    /// 分类名（唯一，供展示）。
    pub name: String,
    /// 目标 DSCP（0-63）。
    pub dscp: u8,
    /// 入向接口逻辑名；空 = 任意接口。
    pub ingress_iface: String,
    /// 协议名（tcp|udp|icmp|icmp6|any）。
    pub proto: String,
    /// 源端口（0 = 任意）。
    pub src_port: u16,
    /// 目的端口（0 = 任意）。
    pub dst_port: u16,
    /// 每类入口限速（字节/秒）；0 = 不限速。
    pub rate_bps: u64,
    /// 桶容量（突发字节）。
    pub burst_bytes: u32,
    /// 是否启用。
    pub enabled: bool,
}

/// 运行时源 IP 速率限制规则行（`rate_limit_rules`）。
#[derive(Debug, Clone)]
pub struct RateLimitRow {
    pub id: Option<i64>,
    /// 源地址（IPv4 / IPv6）。
    pub src_ip: IpAddr,
    /// 每秒令牌数（pps）。
    pub rate: u32,
    /// 桶容量（突发包数）。
    pub burst: u32,
    /// 是否启用。
    pub enabled: bool,
}

/// 运行时每源并发连接数限制规则行（`conn_limit_rules`）。
#[derive(Debug, Clone)]
pub struct ConnLimitRow {
    pub id: Option<i64>,
    /// 源地址（IPv4 / IPv6）。
    pub src_ip: IpAddr,
    /// 允许的最大并发连接数。
    pub max_conns: u32,
    /// 是否启用。
    pub enabled: bool,
}

/// 运行时 DNAT 端口转发规则行（`nat_rules`）。
#[derive(Debug, Clone)]
pub struct NatRuleRow {
    pub id: Option<i64>,
    /// 公网（WAN）目的 IP（IPv4）。
    pub dst_ip: std::net::Ipv4Addr,
    /// 公网目的端口。
    pub dst_port: u16,
    /// tcp | udp。
    pub proto: String,
    /// 内部服务器 IP（IPv4）。
    pub to_ip: std::net::Ipv4Addr,
    /// 内部服务器端口。
    pub to_port: u16,
    /// 是否启用。
    pub enabled: bool,
}

/// 运行时 Zone 策略行（`zone_policies`）。
#[derive(Debug, Clone)]
pub struct ZonePolicyRow {
    pub id: Option<i64>,
    /// 源接口（逻辑名）。
    pub src_interface: String,
    /// 目的接口（逻辑名）。
    pub dst_interface: String,
    /// accept | drop。
    pub action: String,
    /// 是否启用。
    pub enabled: bool,
}

/// 运行时 SYN Flood 全局防护配置行（`syn_flood_config` 单行）。
#[derive(Debug, Clone)]
pub struct SynFloodRow {
    /// 每源 IP 新建连接（SYN）速率上限（pps）；0 = 关闭。
    pub rate_pps: u32,
    /// 令牌桶突发容量。
    pub burst: u32,
    /// 每源 IP 半开连接数上限；0 = 关闭。
    pub max_half_open: u32,
}

impl Persist {
    /// 打开（必要时创建）数据库并建表。
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create db dir {}", parent.display()))?;
            }
        }
        let p = Self {
            path: path.to_path_buf(),
        };
        p.with_conn(|c| {
            c.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS suricata_rules (
                     id        INTEGER PRIMARY KEY AUTOINCREMENT,
                     text      TEXT NOT NULL,
                     enabled   INTEGER NOT NULL DEFAULT 1
                 );
                 CREATE TABLE IF NOT EXISTS blocklist (
                     ip          TEXT PRIMARY KEY,
                     reason      TEXT NOT NULL DEFAULT '',
                     added_unix  INTEGER NOT NULL,
                     expire_unix INTEGER
                 );
                 CREATE TABLE IF NOT EXISTS qos_classes (
                     id            INTEGER PRIMARY KEY AUTOINCREMENT,
                     name          TEXT NOT NULL,
                     dscp          INTEGER NOT NULL DEFAULT 0,
                     ingress_iface TEXT NOT NULL DEFAULT '',
                     proto         TEXT NOT NULL DEFAULT 'any',
                     src_port      INTEGER NOT NULL DEFAULT 0,
                     dst_port      INTEGER NOT NULL DEFAULT 0,
                     rate_bps      INTEGER NOT NULL DEFAULT 0,
                     burst_bytes   INTEGER NOT NULL DEFAULT 16000,
                     enabled       INTEGER NOT NULL DEFAULT 1
                 );
                 CREATE TABLE IF NOT EXISTS rate_limit_rules (
                     id      INTEGER PRIMARY KEY AUTOINCREMENT,
                     src_ip  TEXT NOT NULL,
                     rate    INTEGER NOT NULL,
                     burst   INTEGER NOT NULL DEFAULT 1000,
                     enabled INTEGER NOT NULL DEFAULT 1
                 );
                 CREATE TABLE IF NOT EXISTS conn_limit_rules (
                     id        INTEGER PRIMARY KEY AUTOINCREMENT,
                     src_ip    TEXT NOT NULL,
                     max_conns INTEGER NOT NULL,
                     enabled   INTEGER NOT NULL DEFAULT 1
                 );
                 CREATE TABLE IF NOT EXISTS nat_rules (
                     id       INTEGER PRIMARY KEY AUTOINCREMENT,
                     dst_ip   TEXT NOT NULL,
                     dst_port INTEGER NOT NULL,
                     proto    TEXT NOT NULL DEFAULT 'tcp',
                     to_ip    TEXT NOT NULL,
                     to_port  INTEGER NOT NULL,
                     enabled  INTEGER NOT NULL DEFAULT 1
                 );
                 CREATE TABLE IF NOT EXISTS zone_policies (
                     id             INTEGER PRIMARY KEY AUTOINCREMENT,
                     src_interface  TEXT NOT NULL,
                     dst_interface  TEXT NOT NULL,
                     action         TEXT NOT NULL,
                     enabled        INTEGER NOT NULL DEFAULT 1
                 );
                 CREATE TABLE IF NOT EXISTS syn_flood_config (
                     id            INTEGER PRIMARY KEY CHECK (id = 1),
                     rate_pps      INTEGER NOT NULL DEFAULT 0,
                     burst         INTEGER NOT NULL DEFAULT 100,
                     max_half_open INTEGER NOT NULL DEFAULT 0
                 );",
            )
            .context("init schema")?;
            // 迁移：旧库含解析出的头部列（sid/action/proto/src_ip/dst_ip/src_port/dst_port/
            // comment/created_at/updated_at），仅保留 text/enabled，其余重建。
            let cols: Vec<String> = c
                .prepare("PRAGMA table_info(suricata_rules)")
                .context("table_info")?
                .query_map([], |r| r.get::<_, String>(1))
                .context("query table_info")?
                .filter_map(|r| r.ok())
                .collect();
            if cols.len() > 3 {
                c.execute_batch(
                    "CREATE TABLE suricata_rules_new (
                         id      INTEGER PRIMARY KEY AUTOINCREMENT,
                         text    TEXT NOT NULL,
                         enabled INTEGER NOT NULL DEFAULT 1
                     );
                     INSERT INTO suricata_rules_new (id, text, enabled)
                         SELECT id, text, enabled FROM suricata_rules;
                     DROP TABLE suricata_rules;
                     ALTER TABLE suricata_rules_new RENAME TO suricata_rules;",
                )
                .context("migrate suricata_rules schema")?;
            }
            Ok(())
        })?;
        Ok(p)
    }

    fn with_conn<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = Connection::open(&self.path).context("open sqlite db")?;
        f(&conn)
    }

    /// 读取全部 Suricata 规则（按 id 升序）。
    pub fn load_suricata_rules(&self) -> Result<Vec<SuricataRuleRow>> {
        self.with_conn(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, text, enabled
                     FROM suricata_rules ORDER BY id",
                )
                .context("prepare load_suricata_rules")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(SuricataRuleRow {
                        id: Some(r.get(0)?),
                        text: r.get(1)?,
                        enabled: r.get(2)?,
                    })
                })
                .context("query suricata_rules")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("read suricata rule row")?);
            }
            Ok(out)
        })
    }

    /// 写入（insert）一条 Suricata 规则，返回新 id。
    pub fn insert_suricata_rule(&self, row: &SuricataRuleRow) -> Result<i64> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO suricata_rules (text, enabled)
                 VALUES (?1, ?2)",
                rusqlite::params![row.text, row.enabled],
            )
            .context("insert suricata rule")?;
            Ok(c.last_insert_rowid())
        })
    }

    /// 按 id 更新规则文本（PUT 用）。
    pub fn update_suricata_rule(&self, id: i64, row: &SuricataRuleRow) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE suricata_rules SET text=?1 WHERE id=?2",
                    rusqlite::params![row.text, id],
                )
                .context("update suricata rule")?;
            Ok(n > 0)
        })
    }

    /// 按 id 更新启用字段（PATCH 用）。
    pub fn patch_suricata_rule(&self, id: i64, enabled: bool) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE suricata_rules SET enabled=?1 WHERE id=?2",
                    rusqlite::params![enabled, id],
                )
                .context("patch suricata rule")?;
            Ok(n > 0)
        })
    }

    /// 按 id 删除一条 Suricata 规则。
    pub fn delete_suricata_rule(&self, id: i64) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "DELETE FROM suricata_rules WHERE id = ?1",
                    rusqlite::params![id],
                )
                .context("delete suricata rule")?;
            Ok(n > 0)
        })
    }

    /// 按 id 列表批量删除，返回实际删除条数。
    pub fn delete_suricata_rules(&self, ids: &[i64]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        self.with_conn(|c| {
            let mut removed = 0;
            for id in ids {
                let n = c
                    .execute(
                        "DELETE FROM suricata_rules WHERE id = ?1",
                        rusqlite::params![id],
                    )
                    .context("delete suricata rule")?;
                removed += n;
            }
            Ok(removed)
        })
    }

    /// 清空全部 Suricata 规则。
    pub fn clear_suricata_rules(&self) -> Result<()> {
        self.with_conn(|c| {
            c.execute("DELETE FROM suricata_rules", [])
                .context("clear suricata rules")?;
            Ok(())
        })
    }

    /// 读取未过期的封禁记录（按 ip 文本排序），并顺带清除已过期条目。
    ///
    /// daemon 停机期间到期的封禁在下次启动时被丢弃，不会重新封禁。
    pub fn load_active_blocklist(&self, now_unix: u64) -> Result<Vec<BlocklistRow>> {
        self.with_conn(|c| {
            c.execute(
                "DELETE FROM blocklist
                 WHERE expire_unix IS NOT NULL AND expire_unix <= ?1",
                params![now_unix as i64],
            )
            .context("prune expired blocklist")?;
            let mut stmt = c
                .prepare(
                    "SELECT ip, reason, added_unix, expire_unix
                     FROM blocklist ORDER BY ip",
                )
                .context("prepare load_blocklist")?;
            let rows = stmt
                .query_map([], |r| {
                    let ip: String = r.get(0)?;
                    let ip: IpAddr = ip.parse().map_err(|e: std::net::AddrParseError| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(e),
                        )
                    })?;
                    Ok(BlocklistRow {
                        ip,
                        reason: r.get(1)?,
                        added_unix: r.get::<_, i64>(2)? as u64,
                        expire_unix: r.get::<_, Option<i64>>(3)?.map(|e| e as u64),
                    })
                })
                .context("query blocklist")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("read blocklist row")?);
            }
            Ok(out)
        })
    }

    /// 写入（upsert）一条封禁记录；同 IP 重复封禁覆盖旧记录。
    pub fn upsert_blocklist(&self, row: &BlocklistRow) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                "INSERT OR REPLACE INTO blocklist (ip, reason, added_unix, expire_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    row.ip.to_string(),
                    row.reason,
                    row.added_unix as i64,
                    row.expire_unix.map(|e| e as i64),
                ],
            )
            .context("upsert blocklist")?;
            Ok(())
        })
    }

    /// 删除一条封禁记录。
    pub fn delete_blocklist(&self, ip: &IpAddr) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                "DELETE FROM blocklist WHERE ip = ?1",
                params![ip.to_string()],
            )
            .context("delete blocklist")?;
            Ok(())
        })
    }

    /// 读取全部 QoS 分类（按 id 升序）。
    pub fn load_qos_classes(&self) -> Result<Vec<QosClassRow>> {
        self.with_conn(|c| {
            let mut stmt = c
                .prepare(
                    "SELECT id, name, dscp, ingress_iface, proto, src_port, dst_port,
                            rate_bps, burst_bytes, enabled
                     FROM qos_classes ORDER BY id",
                )
                .context("prepare load_qos_classes")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(QosClassRow {
                        id: Some(r.get(0)?),
                        name: r.get(1)?,
                        dscp: r.get::<_, i64>(2)? as u8,
                        ingress_iface: r.get(3)?,
                        proto: r.get(4)?,
                        src_port: r.get::<_, i64>(5)? as u16,
                        dst_port: r.get::<_, i64>(6)? as u16,
                        rate_bps: r.get::<_, i64>(7)? as u64,
                        burst_bytes: r.get::<_, i64>(8)? as u32,
                        enabled: r.get(9)?,
                    })
                })
                .context("query qos_classes")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("read qos class row")?);
            }
            Ok(out)
        })
    }

    /// 写入（insert）一条 QoS 分类，返回新 id。
    pub fn insert_qos_class(&self, row: &QosClassRow) -> Result<i64> {
        self.with_conn(|c| {
            c.execute(
                "INSERT INTO qos_classes
                     (name, dscp, ingress_iface, proto, src_port, dst_port,
                      rate_bps, burst_bytes, enabled)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    row.name,
                    row.dscp as i64,
                    row.ingress_iface,
                    row.proto,
                    row.src_port as i64,
                    row.dst_port as i64,
                    row.rate_bps as i64,
                    row.burst_bytes as i64,
                    row.enabled,
                ],
            )
            .context("insert qos class")?;
            Ok(c.last_insert_rowid())
        })
    }

    /// 按 id 更新一条 QoS 分类（PUT 用）。
    pub fn update_qos_class(&self, id: i64, row: &QosClassRow) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE qos_classes SET name=?1, dscp=?2, ingress_iface=?3, proto=?4,
                            src_port=?5, dst_port=?6, rate_bps=?7, burst_bytes=?8
                     WHERE id=?9",
                    params![
                        row.name,
                        row.dscp as i64,
                        row.ingress_iface,
                        row.proto,
                        row.src_port as i64,
                        row.dst_port as i64,
                        row.rate_bps as i64,
                        row.burst_bytes as i64,
                        id,
                    ],
                )
                .context("update qos class")?;
            Ok(n > 0)
        })
    }

    /// 按 id 更新启用字段（PATCH 用）。
    pub fn patch_qos_class(&self, id: i64, enabled: bool) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE qos_classes SET enabled=?1 WHERE id=?2",
                    params![enabled, id],
                )
                .context("patch qos class")?;
            Ok(n > 0)
        })
    }

    /// 按 id 删除一条 QoS 分类。
    pub fn delete_qos_class(&self, id: i64) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute("DELETE FROM qos_classes WHERE id = ?1", params![id])
                .context("delete qos class")?;
            Ok(n > 0)
        })
    }

    /// 清空全部 QoS 分类。
    pub fn clear_qos_classes(&self) -> Result<()> {
        self.with_conn(|c| {
            c.execute("DELETE FROM qos_classes", [])
                .context("clear qos classes")?;
            Ok(())
        })
    }

    // ============================================================================
    // 运行时速率限制规则（`rate_limit_rules`）
    // ============================================================================

    /// 读取全部速率限制规则（按 id 升序）。
    pub fn load_rate_limits(&self) -> Result<Vec<RateLimitRow>> {
        self.with_conn(|c| {
            let mut stmt = c
                .prepare("SELECT id, src_ip, rate, burst, enabled FROM rate_limit_rules ORDER BY id")
                .context("prepare load_rate_limits")?;
            let rows = stmt
                .query_map([], |r| {
                    let src_ip: String = r.get(1)?;
                    let src_ip: IpAddr = src_ip
                        .parse()
                        .map_err(|e: std::net::AddrParseError| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;
                    Ok(RateLimitRow {
                        id: Some(r.get(0)?),
                        src_ip,
                        rate: r.get::<_, i64>(2)? as u32,
                        burst: r.get::<_, i64>(3)? as u32,
                        enabled: r.get(4)?,
                    })
                })
                .context("query rate_limit_rules")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("read rate limit row")?);
            }
            Ok(out)
        })
    }

    /// 写入（insert）一条速率限制规则，返回新 id。`id` 可自定义（唯一即可）。
    pub fn insert_rate_limit(&self, row: &RateLimitRow) -> Result<i64> {
        self.with_conn(|c| {
            match row.id {
                Some(id) => {
                    c.execute(
                        "INSERT INTO rate_limit_rules (id, src_ip, rate, burst, enabled)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id, row.src_ip.to_string(), row.rate as i64, row.burst as i64, row.enabled],
                    )
                    .context("insert rate limit with custom id")?;
                    Ok(id)
                }
                None => {
                    c.execute(
                        "INSERT INTO rate_limit_rules (src_ip, rate, burst, enabled)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![row.src_ip.to_string(), row.rate as i64, row.burst as i64, row.enabled],
                    )
                    .context("insert rate limit")?;
                    Ok(c.last_insert_rowid())
                }
            }
        })
    }

    /// 按 id 更新一条速率限制规则（PUT 用）。
    pub fn update_rate_limit(&self, id: i64, row: &RateLimitRow) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE rate_limit_rules SET src_ip=?1, rate=?2, burst=?3 WHERE id=?4",
                    params![row.src_ip.to_string(), row.rate as i64, row.burst as i64, id],
                )
                .context("update rate limit")?;
            Ok(n > 0)
        })
    }

    /// 按 id 更新启用字段（PATCH 用）。
    pub fn patch_rate_limit(&self, id: i64, enabled: bool) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE rate_limit_rules SET enabled=?1 WHERE id=?2",
                    params![enabled, id],
                )
                .context("patch rate limit")?;
            Ok(n > 0)
        })
    }

    /// 按 id 删除一条速率限制规则。
    pub fn delete_rate_limit(&self, id: i64) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute("DELETE FROM rate_limit_rules WHERE id = ?1", params![id])
                .context("delete rate limit")?;
            Ok(n > 0)
        })
    }

    // ============================================================================
    // 运行时每源并发连接数限制规则（`conn_limit_rules`）
    // ============================================================================

    /// 读取全部并发连接数限制规则（按 id 升序）。
    pub fn load_conn_limits(&self) -> Result<Vec<ConnLimitRow>> {
        self.with_conn(|c| {
            let mut stmt = c
                .prepare("SELECT id, src_ip, max_conns, enabled FROM conn_limit_rules ORDER BY id")
                .context("prepare load_conn_limits")?;
            let rows = stmt
                .query_map([], |r| {
                    let src_ip: String = r.get(1)?;
                    let src_ip: IpAddr = src_ip
                        .parse()
                        .map_err(|e: std::net::AddrParseError| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;
                    Ok(ConnLimitRow {
                        id: Some(r.get(0)?),
                        src_ip,
                        max_conns: r.get::<_, i64>(2)? as u32,
                        enabled: r.get(3)?,
                    })
                })
                .context("query conn_limit_rules")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("read conn limit row")?);
            }
            Ok(out)
        })
    }

    /// 写入（insert）一条并发连接数限制规则，返回新 id。`id` 可自定义。
    pub fn insert_conn_limit(&self, row: &ConnLimitRow) -> Result<i64> {
        self.with_conn(|c| {
            match row.id {
                Some(id) => {
                    c.execute(
                        "INSERT INTO conn_limit_rules (id, src_ip, max_conns, enabled)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![id, row.src_ip.to_string(), row.max_conns as i64, row.enabled],
                    )
                    .context("insert conn limit with custom id")?;
                    Ok(id)
                }
                None => {
                    c.execute(
                        "INSERT INTO conn_limit_rules (src_ip, max_conns, enabled)
                         VALUES (?1, ?2, ?3)",
                        params![row.src_ip.to_string(), row.max_conns as i64, row.enabled],
                    )
                    .context("insert conn limit")?;
                    Ok(c.last_insert_rowid())
                }
            }
        })
    }

    /// 按 id 更新一条并发连接数限制规则（PUT 用）。
    pub fn update_conn_limit(&self, id: i64, row: &ConnLimitRow) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE conn_limit_rules SET src_ip=?1, max_conns=?2 WHERE id=?3",
                    params![row.src_ip.to_string(), row.max_conns as i64, id],
                )
                .context("update conn limit")?;
            Ok(n > 0)
        })
    }

    /// 按 id 更新启用字段（PATCH 用）。
    pub fn patch_conn_limit(&self, id: i64, enabled: bool) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE conn_limit_rules SET enabled=?1 WHERE id=?2",
                    params![enabled, id],
                )
                .context("patch conn limit")?;
            Ok(n > 0)
        })
    }

    /// 按 id 删除一条并发连接数限制规则。
    pub fn delete_conn_limit(&self, id: i64) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute("DELETE FROM conn_limit_rules WHERE id = ?1", params![id])
                .context("delete conn limit")?;
            Ok(n > 0)
        })
    }

    // ============================================================================
    // 运行时 DNAT 端口转发规则（`nat_rules`）
    // ============================================================================

    /// 读取全部 DNAT 规则（按 id 升序）。
    pub fn load_nat_rules(&self) -> Result<Vec<NatRuleRow>> {
        self.with_conn(|c| {
            let mut stmt = c
                .prepare("SELECT id, dst_ip, dst_port, proto, to_ip, to_port, enabled FROM nat_rules ORDER BY id")
                .context("prepare load_nat_rules")?;
            let rows = stmt
                .query_map([], |r| {
                    let dst_ip: String = r.get(1)?;
                    let dst_ip = dst_ip
                        .parse()
                        .map_err(|e: std::net::AddrParseError| {
                            rusqlite::Error::FromSqlConversionFailure(
                                1,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;
                    let to_ip: String = r.get(4)?;
                    let to_ip = to_ip
                        .parse()
                        .map_err(|e: std::net::AddrParseError| {
                            rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Text,
                                Box::new(e),
                            )
                        })?;
                    Ok(NatRuleRow {
                        id: Some(r.get(0)?),
                        dst_ip,
                        dst_port: r.get::<_, i64>(2)? as u16,
                        proto: r.get(3)?,
                        to_ip,
                        to_port: r.get::<_, i64>(5)? as u16,
                        enabled: r.get(6)?,
                    })
                })
                .context("query nat_rules")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("read nat rule row")?);
            }
            Ok(out)
        })
    }

    /// 写入（insert）一条 DNAT 规则，返回新 id。`id` 可自定义。
    pub fn insert_nat_rule(&self, row: &NatRuleRow) -> Result<i64> {
        self.with_conn(|c| {
            match row.id {
                Some(id) => {
                    c.execute(
                        "INSERT INTO nat_rules (id, dst_ip, dst_port, proto, to_ip, to_port, enabled)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            id,
                            row.dst_ip.to_string(),
                            row.dst_port as i64,
                            row.proto,
                            row.to_ip.to_string(),
                            row.to_port as i64,
                            row.enabled,
                        ],
                    )
                    .context("insert nat rule with custom id")?;
                    Ok(id)
                }
                None => {
                    c.execute(
                        "INSERT INTO nat_rules (dst_ip, dst_port, proto, to_ip, to_port, enabled)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            row.dst_ip.to_string(),
                            row.dst_port as i64,
                            row.proto,
                            row.to_ip.to_string(),
                            row.to_port as i64,
                            row.enabled,
                        ],
                    )
                    .context("insert nat rule")?;
                    Ok(c.last_insert_rowid())
                }
            }
        })
    }

    /// 按 id 更新一条 DNAT 规则（PUT 用）。
    pub fn update_nat_rule(&self, id: i64, row: &NatRuleRow) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE nat_rules SET dst_ip=?1, dst_port=?2, proto=?3, to_ip=?4, to_port=?5
                     WHERE id=?6",
                    params![
                        row.dst_ip.to_string(),
                        row.dst_port as i64,
                        row.proto,
                        row.to_ip.to_string(),
                        row.to_port as i64,
                        id,
                    ],
                )
                .context("update nat rule")?;
            Ok(n > 0)
        })
    }

    /// 按 id 更新启用字段（PATCH 用）。
    pub fn patch_nat_rule(&self, id: i64, enabled: bool) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE nat_rules SET enabled=?1 WHERE id=?2",
                    params![enabled, id],
                )
                .context("patch nat rule")?;
            Ok(n > 0)
        })
    }

    /// 按 id 删除一条 DNAT 规则。
    pub fn delete_nat_rule(&self, id: i64) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute("DELETE FROM nat_rules WHERE id = ?1", params![id])
                .context("delete nat rule")?;
            Ok(n > 0)
        })
    }

    // ============================================================================
    // 运行时 Zone 策略（`zone_policies`）
    // ============================================================================

    /// 读取全部 Zone 策略（按 id 升序）。
    pub fn load_zone_policies(&self) -> Result<Vec<ZonePolicyRow>> {
        self.with_conn(|c| {
            let mut stmt = c
                .prepare("SELECT id, src_interface, dst_interface, action, enabled FROM zone_policies ORDER BY id")
                .context("prepare load_zone_policies")?;
            let rows = stmt
                .query_map([], |r| {
                    Ok(ZonePolicyRow {
                        id: Some(r.get(0)?),
                        src_interface: r.get(1)?,
                        dst_interface: r.get(2)?,
                        action: r.get(3)?,
                        enabled: r.get(4)?,
                    })
                })
                .context("query zone_policies")?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row.context("read zone policy row")?);
            }
            Ok(out)
        })
    }

    /// 写入（insert）一条 Zone 策略，返回新 id。`id` 可自定义。
    pub fn insert_zone_policy(&self, row: &ZonePolicyRow) -> Result<i64> {
        self.with_conn(|c| {
            match row.id {
                Some(id) => {
                    c.execute(
                        "INSERT INTO zone_policies (id, src_interface, dst_interface, action, enabled)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![id, row.src_interface, row.dst_interface, row.action, row.enabled],
                    )
                    .context("insert zone policy with custom id")?;
                    Ok(id)
                }
                None => {
                    c.execute(
                        "INSERT INTO zone_policies (src_interface, dst_interface, action, enabled)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![row.src_interface, row.dst_interface, row.action, row.enabled],
                    )
                    .context("insert zone policy")?;
                    Ok(c.last_insert_rowid())
                }
            }
        })
    }

    /// 按 id 更新一条 Zone 策略（PUT 用）。
    pub fn update_zone_policy(&self, id: i64, row: &ZonePolicyRow) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE zone_policies SET src_interface=?1, dst_interface=?2, action=?3
                     WHERE id=?4",
                    params![row.src_interface, row.dst_interface, row.action, id],
                )
                .context("update zone policy")?;
            Ok(n > 0)
        })
    }

    /// 按 id 更新启用字段（PATCH 用）。
    pub fn patch_zone_policy(&self, id: i64, enabled: bool) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute(
                    "UPDATE zone_policies SET enabled=?1 WHERE id=?2",
                    params![enabled, id],
                )
                .context("patch zone policy")?;
            Ok(n > 0)
        })
    }

    /// 按 id 删除一条 Zone 策略。
    pub fn delete_zone_policy(&self, id: i64) -> Result<bool> {
        self.with_conn(|c| {
            let n = c
                .execute("DELETE FROM zone_policies WHERE id = ?1", params![id])
                .context("delete zone policy")?;
            Ok(n > 0)
        })
    }

    // ============================================================================
    // 运行时 SYN Flood 防护配置（`syn_flood_config` 单行）
    // ============================================================================

    /// 读取 SYN Flood 防护配置（无行则返回默认）。
    pub fn load_syn_flood(&self) -> Result<SynFloodRow> {
        self.with_conn(|c| {
            let row = c
                .query_row(
                    "SELECT rate_pps, burst, max_half_open FROM syn_flood_config WHERE id = 1",
                    [],
                    |r| {
                        Ok(SynFloodRow {
                            rate_pps: r.get::<_, i64>(0)? as u32,
                            burst: r.get::<_, i64>(1)? as u32,
                            max_half_open: r.get::<_, i64>(2)? as u32,
                        })
                    },
                )
                .optional()
                .context("load syn_flood config")?;
            Ok(row.unwrap_or(SynFloodRow {
                rate_pps: 0,
                burst: 100,
                max_half_open: 0,
            }))
        })
    }

    /// 写入（upsert）SYN Flood 防护配置（单行）。
    pub fn save_syn_flood(&self, row: &SynFloodRow) -> Result<()> {
        self.with_conn(|c| {
            c.execute(
                "INSERT OR REPLACE INTO syn_flood_config (id, rate_pps, burst, max_half_open)
                 VALUES (1, ?1, ?2, ?3)",
                params![row.rate_pps as i64, row.burst as i64, row.max_half_open as i64],
            )
            .context("save syn_flood config")?;
            Ok(())
        })
    }

    /// 交换两条规则的执行顺序：将两条记录的 id 互换（id 即执行顺序）。
    ///
    /// `table`/`id_col` 指向规则表主键列；两行必须在同一表中且均存在。
    pub fn swap_ids(&self, table: &str, id_col: &str, id_a: i64, id_b: i64) -> Result<bool> {
        if id_a == id_b {
            return Ok(false);
        }
        self.with_conn(|c| {
            c.execute("BEGIN IMMEDIATE", [])
                .context("begin swap transaction")?;
            let exists_a: bool = c
                .query_row(
                    &format!("SELECT 1 FROM {table} WHERE {id_col} = ?1"),
                    params![id_a],
                    |_| Ok(true),
                )
                .optional()
                .context("check id_a")?
                .unwrap_or(false);
            let exists_b: bool = c
                .query_row(
                    &format!("SELECT 1 FROM {table} WHERE {id_col} = ?1"),
                    params![id_b],
                    |_| Ok(true),
                )
                .optional()
                .context("check id_b")?
                .unwrap_or(false);
            if !exists_a || !exists_b {
                c.execute("ROLLBACK", []).ok();
                return Ok(false);
            }
            // 先移到负数临时值，避免唯一约束冲突。
            c.execute(
                &format!("UPDATE {table} SET {id_col} = -1 WHERE {id_col} = ?1"),
                params![id_a],
            )
            .context("swap step 1")?;
            c.execute(
                &format!("UPDATE {table} SET {id_col} = ?1 WHERE {id_col} = ?2"),
                params![id_a, id_b],
            )
            .context("swap step 2")?;
            c.execute(
                &format!("UPDATE {table} SET {id_col} = ?1 WHERE {id_col} = -1"),
                params![id_b],
            )
            .context("swap step 3")?;
            c.execute("COMMIT", []).context("commit swap")?;
            Ok(true)
        })
    }
}
