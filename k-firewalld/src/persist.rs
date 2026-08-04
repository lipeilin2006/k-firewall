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
use rusqlite::{Connection, params};

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

impl Persist {
    /// 打开（必要时创建）数据库并建表。
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create db dir {}", parent.display()))?;
            }
        }
        let p = Self { path: path.to_path_buf() };
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
                .execute("DELETE FROM suricata_rules WHERE id = ?1", rusqlite::params![id])
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
                    .execute("DELETE FROM suricata_rules WHERE id = ?1", rusqlite::params![id])
                    .context("delete suricata rule")?;
                removed += n;
            }
            Ok(removed)
        })
    }

    /// 清空全部 Suricata 规则。
    pub fn clear_suricata_rules(&self) -> Result<()> {
        self.with_conn(|c| {
            c.execute("DELETE FROM suricata_rules", []).context("clear suricata rules")?;
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
            c.execute("DELETE FROM blocklist WHERE ip = ?1", params![ip.to_string()])
                .context("delete blocklist")?;
            Ok(())
        })
    }
}
