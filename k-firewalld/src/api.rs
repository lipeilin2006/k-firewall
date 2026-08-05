use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, anyhow};
use axum::body::Body;
use axum::extract::{Path as AxumPath, Query, Request, State};
use axum::http::StatusCode;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use k_firewall_common::BlockEntry;
use k_firewall_common::maps::{DnatKey, DnatValue, IpKey, ZoneEntry};
use k_firewall_common::api::{
    BlockRequest, BlockedEntryOut, BlockedOut, BlocklistEntryOut, BlocklistOut, ConfigDiffOut,
    ConfigRestoreOut, ConfigValidateOut, ConnLimitDeleteRequest, ConnLimitListOut, ConnLimitOut,
    ConnLimitRequest, ConnLimitUpdateRequest, Error, InterfaceInfo, InterfaceStats,
    InterfaceStatsOut, InterfacesOut, NatRuleDeleteRequest, NatRuleListOut, NatRuleOut,
    NatRuleRequest, NatRuleUpdateRequest, OrderSwapRequest, QosClassDeleteRequest, QosClassListOut,
    QosClassOut, QosClassPatchRequest, QosClassRequest, QosClassUpdateRequest,
    RateLimitDeleteRequest, RateLimitListOut, RateLimitOut, RateLimitRequest, RateLimitUpdateRequest,
    SessionDeleteRequest, SessionListQuery, SessionOut, SessionsDeleteOut, SessionsOut, StatsOut,
    Status, SuricataPrefilterStats, SuricataRuleDeleteRequest, SuricataRuleImportOut,
    SuricataRuleImportRequest, SuricataRuleListOut, SuricataRuleOut, SuricataRulePatchRequest,
    SuricataRuleRequest, SuricataRuleUpdateRequest, SynFloodOut, SynFloodRequest,
    ZonePolicyDeleteRequest, ZonePolicyListOut, ZonePolicyOut, ZonePolicyRequest,
    ZonePolicyUpdateRequest,
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::net::UnixListener;
use tracing::{info, warn};

use crate::config::Config;
use crate::ebpf_loader::EbpfHandle;
use crate::persist::Persist;

/// 当前 unix 秒。
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// daemon 共享状态（API handler / 后台任务共用）。
pub struct AppState {
    pub handle: tokio::sync::Mutex<EbpfHandle>,
    pub blocked: Mutex<HashMap<IpAddr, BlockEntry>>,
    pub iface: String,
    /// 运行时 Suricata 规则（全文 + 解析出的头部字段，SQLite 持久化）。
    pub suricata_rules: Mutex<Vec<crate::suricata_rules::SuriRule>>,
    /// 下一条 Suricata 规则 id（无持久化时使用）。
    pub next_suri_rule_id: AtomicU64,
    /// 运行时 QoS 分类（SQLite 持久化，热同步 `QOS_CLASSES`）。
    pub qos_classes: Mutex<Vec<crate::persist::QosClassRow>>,
    /// 下一条 QoS 分类 id（无持久化时使用）。
    pub next_qos_class_id: AtomicU64,
    /// 运行时源 IP 速率限制规则（SQLite 持久化，热同步 `RATE_LIMITS`）。
    pub rate_limits: Mutex<Vec<crate::persist::RateLimitRow>>,
    /// 下一条速率限制规则 id（无持久化时使用）。
    pub next_rate_limit_id: AtomicU64,
    /// 运行时每源并发连接数限制规则（SQLite 持久化，热同步 `CONN_LIMITS`）。
    pub conn_limits: Mutex<Vec<crate::persist::ConnLimitRow>>,
    /// 下一条并发连接数限制规则 id（无持久化时使用）。
    pub next_conn_limit_id: AtomicU64,
    /// 运行时 DNAT 端口转发规则（SQLite 持久化，热同步 `DNAT_RULES`）。
    pub nat_rules: Mutex<Vec<crate::persist::NatRuleRow>>,
    /// 下一条 DNAT 规则 id（无持久化时使用）。
    pub next_nat_rule_id: AtomicU64,
    /// 运行时 Zone 策略（SQLite 持久化，热同步 `ZONE`；id 顺序即执行顺序）。
    pub zone_policies: Mutex<Vec<crate::persist::ZonePolicyRow>>,
    /// 下一条 Zone 策略 id（无持久化时使用）。
    pub next_zone_policy_id: AtomicU64,
    /// 运行时 SYN Flood 防护配置（SQLite 持久化，热同步 `CONFIG_SYN_*`）。
    pub syn_flood: Mutex<crate::persist::SynFloodRow>,
    /// `suricata.prefilter` 配置（XDP 规则头预过滤开关；可热改）。
    pub suricata_prefilter: AtomicBool,
    /// 运行时规则持久化（未配置 `daemon.db_path` 时为空）。
    pub persist: Option<Persist>,
    /// HTTP API 认证 Key 列表（空 = 不启用认证）。
    api_keys: Vec<String>,
    pub started: SystemTime,
    /// 当前生效配置文件的路径（`GET/POST /api/v1/system/config` 用；由 main 传入）。
    config_path: Option<PathBuf>,
    /// 逻辑接口配置（`GET /api/v1/system/interfaces` 只读展示）。
    interfaces: Vec<crate::config::InterfaceConfig>,
    /// 挂载 XDP 的物理网卡（去重；`/operational/stats/interfaces` 数据源）。
    attach_ifaces: Vec<String>,
    /// SSE 事件广播（`GET /api/v1/operational/events` 订阅；无人订阅时自动丢弃）。
    event_tx: tokio::sync::broadcast::Sender<Value>,
}

impl AppState {
    /// 广播一条运维事件（SSE）。无人订阅时静默丢弃。
    pub fn emit_event(&self, event: &str, data: Value) {
        let _ = self.event_tx.send(json!({"event": event, "data": data}));
    }

    pub fn new(handle: EbpfHandle, config: Config, config_path: Option<PathBuf>) -> Result<Self> {
        // 持久化：加载 DB 中的 Suricata 规则（若配置了 db_path）。
        let persist = config.daemon.db_path.as_ref().map(|p| Persist::open(p));
        let persist = match persist {
            Some(Ok(p)) => {
                info!("runtime rule persistence enabled at {}", p_path(&config));
                Some(p)
            }
            Some(Err(e)) => {
                warn!("persistence disabled: {e:#}");
                None
            }
            None => None,
        };

        // 恢复持久化的封禁记录：重新写入内核 BLOCKED map 并重建内存表，
        // 避免重启导致已封禁 IP 自动解封。启动期间已到期的条目在加载时被清除。
        let mut handle = handle;
        let blocked = {
            let mut map: HashMap<IpAddr, BlockEntry> = HashMap::new();
            if let Some(p) = &persist {
                match p.load_active_blocklist(now_unix()) {
                    Ok(rows) => {
                        for row in rows {
                            if let Err(e) = handle.block(row.ip) {
                                warn!("restore block {} failed: {e:#}", row.ip);
                                continue;
                            }
                            map.insert(
                                row.ip,
                                BlockEntry {
                                    ip: row.ip,
                                    reason: row.reason,
                                    added_unix: row.added_unix,
                                    expire_unix: row.expire_unix,
                                },
                            );
                            info!("restored block {}", row.ip);
                        }
                    }
                    Err(e) => warn!("failed to load blocklist from db: {e:#}"),
                }
            }
            map
        };

        // 恢复持久化的 QoS 分类并同步到 eBPF（QOS_CLASSES）。启动期间
        // 同步失败仅告警：分类仍保留在内存/DB，运行时可重试。
        let qos_classes = {
            let mut rows = Vec::new();
            if let Some(p) = &persist {
                match p.load_qos_classes() {
                    Ok(r) => rows = r,
                    Err(e) => warn!("failed to load qos classes from db: {e:#}"),
                }
            }
            rows
        };
        let mut next_qos_class_id = 1u64;
        for r in &qos_classes {
            if let Some(id) = r.id {
                next_qos_class_id = next_qos_class_id.max(id as u64 + 1);
            }
        }
        {
            let entries: Vec<k_firewall_common::maps::QosConfig> = qos_classes
                .iter()
                .filter(|r| r.enabled)
                .map(|r| qos_config_from_row(r, &config.interfaces))
                .collect();
            if let Err(e) = handle.sync_qos_classes(&entries) {
                warn!("failed to sync qos classes to ebpf: {e:#}");
            }
        }

        // 运行时 NAT 端口转发规则：DB 为空时从配置播种（DB 为运行时事实源），再同步 eBPF。
        let nat_rules = {
            let mut rows = Vec::new();
            if let Some(p) = &persist {
                match p.load_nat_rules() {
                    Ok(r) => rows = r,
                    Err(e) => warn!("failed to load nat rules from db: {e:#}"),
                }
                if rows.is_empty() && !config.nat_rules.is_empty() {
                    for d in &config.nat_rules {
                        if let Err(e) = p.insert_nat_rule(&crate::persist::NatRuleRow {
                            id: None,
                            dst_ip: d.dst_ip,
                            dst_port: d.dst_port,
                            proto: d.proto.clone(),
                            to_ip: d.to_ip,
                            to_port: d.to_port,
                            enabled: true,
                        }) {
                            warn!("failed to seed nat rule from config: {e:#}");
                        }
                    }
                    match p.load_nat_rules() {
                        Ok(r) => rows = r,
                        Err(e) => warn!("failed to reload nat rules: {e:#}"),
                    }
                }
            }
            rows
        };
        let mut next_nat_rule_id = 1u64;
        for r in &nat_rules {
            if let Some(id) = r.id {
                next_nat_rule_id = next_nat_rule_id.max(id as u64 + 1);
            }
        }
        {
            let entries = nat_entries_from_rows(&nat_rules, &config.interfaces);
            if let Err(e) = handle.sync_dnat_rules(&entries) {
                warn!("failed to sync nat rules to ebpf: {e:#}");
            }
        }

        // 运行时源 IP 速率限制规则：DB 为空时从配置播种，再同步 eBPF。
        let rate_limits = {
            let mut rows = Vec::new();
            if let Some(p) = &persist {
                match p.load_rate_limits() {
                    Ok(r) => rows = r,
                    Err(e) => warn!("failed to load rate limits from db: {e:#}"),
                }
                if rows.is_empty() && !config.rate_limit_rules.is_empty() {
                    for rl in &config.rate_limit_rules {
                        if let Err(e) = p.insert_rate_limit(&crate::persist::RateLimitRow {
                            id: None,
                            src_ip: rl.src_ip,
                            rate: rl.rate,
                            burst: rl.burst,
                            enabled: true,
                        }) {
                            warn!("failed to seed rate limit from config: {e:#}");
                        }
                    }
                    match p.load_rate_limits() {
                        Ok(r) => rows = r,
                        Err(e) => warn!("failed to reload rate limits: {e:#}"),
                    }
                }
            }
            rows
        };
        let mut next_rate_limit_id = 1u64;
        for r in &rate_limits {
            if let Some(id) = r.id {
                next_rate_limit_id = next_rate_limit_id.max(id as u64 + 1);
            }
        }
        {
            let entries = rate_entries_from_rows(&rate_limits);
            if let Err(e) = handle.sync_rate_limit_entries(&entries) {
                warn!("failed to sync rate limits to ebpf: {e:#}");
            }
        }

        // 运行时每源并发连接数限制规则：DB 为空时从配置播种，再同步 eBPF。
        let conn_limits = {
            let mut rows = Vec::new();
            if let Some(p) = &persist {
                match p.load_conn_limits() {
                    Ok(r) => rows = r,
                    Err(e) => warn!("failed to load conn limits from db: {e:#}"),
                }
                if rows.is_empty() && !config.conn_limits.is_empty() {
                    for cl in &config.conn_limits {
                        if let Err(e) = p.insert_conn_limit(&crate::persist::ConnLimitRow {
                            id: None,
                            src_ip: cl.src_ip,
                            max_conns: cl.max_conns,
                            enabled: true,
                        }) {
                            warn!("failed to seed conn limit from config: {e:#}");
                        }
                    }
                    match p.load_conn_limits() {
                        Ok(r) => rows = r,
                        Err(e) => warn!("failed to reload conn limits: {e:#}"),
                    }
                }
            }
            rows
        };
        let mut next_conn_limit_id = 1u64;
        for r in &conn_limits {
            if let Some(id) = r.id {
                next_conn_limit_id = next_conn_limit_id.max(id as u64 + 1);
            }
        }
        {
            let entries = conn_entries_from_rows(&conn_limits);
            if let Err(e) = handle.sync_conn_limits(&entries) {
                warn!("failed to sync conn limits to ebpf: {e:#}");
            }
        }

        // 运行时 Zone 策略：DB 为空时从配置播种，再同步 eBPF。
        let zone_policies = {
            let mut rows = Vec::new();
            if let Some(p) = &persist {
                match p.load_zone_policies() {
                    Ok(r) => rows = r,
                    Err(e) => warn!("failed to load zone policies from db: {e:#}"),
                }
                if rows.is_empty() && !config.zone_policies.is_empty() {
                    for z in &config.zone_policies {
                        if let Err(e) = p.insert_zone_policy(&crate::persist::ZonePolicyRow {
                            id: None,
                            src_interface: z.src_interface.clone(),
                            dst_interface: z.dst_interface.clone(),
                            action: z.action.clone(),
                            enabled: true,
                        }) {
                            warn!("failed to seed zone policy from config: {e:#}");
                        }
                    }
                    match p.load_zone_policies() {
                        Ok(r) => rows = r,
                        Err(e) => warn!("failed to reload zone policies: {e:#}"),
                    }
                }
            }
            rows
        };
        let mut next_zone_policy_id = 1u64;
        for r in &zone_policies {
            if let Some(id) = r.id {
                next_zone_policy_id = next_zone_policy_id.max(id as u64 + 1);
            }
        }
        {
            let entries = zone_entries_from_rows(&zone_policies, &config.interfaces);
            if let Err(e) = handle.sync_zone_policies(&entries) {
                warn!("failed to sync zone policies to ebpf: {e:#}");
            }
        }

        // 运行时 SYN Flood 防护配置：DB 无行时回退到配置默认，再同步 eBPF。
        let syn_flood = {
            let row = match &persist {
                Some(p) => match p.load_syn_flood() {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("failed to load syn_flood config from db: {e:#}");
                        crate::persist::SynFloodRow {
                            rate_pps: config.syn_flood.rate_pps,
                            burst: config.syn_flood.burst,
                            max_half_open: config.syn_flood.max_half_open,
                        }
                    }
                },
                None => crate::persist::SynFloodRow {
                    rate_pps: config.syn_flood.rate_pps,
                    burst: config.syn_flood.burst,
                    max_half_open: config.syn_flood.max_half_open,
                },
            };
            if let Err(e) = handle.sync_syn_flood(row.rate_pps, row.burst, row.max_half_open) {
                warn!("failed to sync syn_flood config to ebpf: {e:#}");
            }
            row
        };

        Ok(Self {
            handle: tokio::sync::Mutex::new(handle),
            blocked: Mutex::new(blocked),
            iface: config.primary_iface(),
            suricata_rules: Mutex::new(Vec::new()),
            next_suri_rule_id: AtomicU64::new(1),
            qos_classes: Mutex::new(qos_classes),
            next_qos_class_id: AtomicU64::new(next_qos_class_id),
            rate_limits: Mutex::new(rate_limits),
            next_rate_limit_id: AtomicU64::new(next_rate_limit_id),
            conn_limits: Mutex::new(conn_limits),
            next_conn_limit_id: AtomicU64::new(next_conn_limit_id),
            nat_rules: Mutex::new(nat_rules),
            next_nat_rule_id: AtomicU64::new(next_nat_rule_id),
            zone_policies: Mutex::new(zone_policies),
            next_zone_policy_id: AtomicU64::new(next_zone_policy_id),
            syn_flood: Mutex::new(syn_flood),
            suricata_prefilter: AtomicBool::new(config.suricata.prefilter),
            persist,
            api_keys: config.daemon.api_keys.clone(),
            started: SystemTime::now(),
            config_path,
            interfaces: config.interfaces.clone(),
            attach_ifaces: config.attach_ifaces(),
            event_tx: tokio::sync::broadcast::channel(64).0,
        })
    }

    pub async fn block(&self, ip: IpAddr, seconds: Option<u64>, reason: String) -> Result<()> {
        let now_unix = now_unix();
        let expire_unix = seconds.map(|s| now_unix + s);

        self.handle.lock().await.block(ip)?;
        self.blocked.lock().unwrap().insert(
            ip,
            BlockEntry {
                ip,
                reason: reason.clone(),
                added_unix: now_unix,
                expire_unix,
            },
        );
        if let Some(p) = &self.persist {
            if let Err(e) = p.upsert_blocklist(&crate::persist::BlocklistRow {
                ip,
                reason: reason.clone(),
                added_unix: now_unix,
                expire_unix,
            }) {
                warn!("persist block {} failed: {e:#}", ip);
            }
        }
        self.emit_event(
            "blocked",
            json!({"ip": ip.to_string(), "expire_unix": expire_unix, "reason": reason}),
        );
        Ok(())
    }

    pub async fn unblock(&self, ip: IpAddr) -> Result<()> {
        self.handle.lock().await.unblock(ip)?;
        self.blocked.lock().unwrap().remove(&ip);
        if let Some(p) = &self.persist {
            if let Err(e) = p.delete_blocklist(&ip) {
                warn!("persist unblock {} failed: {e:#}", ip);
            }
        }
        self.emit_event("unblocked", json!({"ip": ip.to_string()}));
        Ok(())
    }

    pub async fn read_stats(&self) -> Result<k_firewall_common::Stats> {
        self.handle.lock().await.read_stats()
    }

    /// 清理过期的连接跟踪条目（CONNTRACK）。
    pub async fn prune_conntrack(&self, cfg: &crate::config::Conntrack) -> Result<()> {
        let mut handle = self.handle.lock().await;
        handle.prune_conntrack(cfg)?;
        Ok(())
    }

    /// 清理过期的分片流条目（FRAG_TRACK）。
    pub async fn prune_frag_track(&self, timeout_secs: u64) -> Result<()> {
        let mut handle = self.handle.lock().await;
        handle.prune_frag_track(timeout_secs)?;
        Ok(())
    }

    /// 校正每源连接数 / 半开数（从 CONNTRACK 真实条目重算 CONN_COUNT / SYN_COUNT）。
    pub async fn reconcile_conn_counts(&self) -> Result<()> {
        let mut handle = self.handle.lock().await;
        handle.reconcile_conn_counts()?;
        Ok(())
    }

    /// 移除已过期的封禁（同步删除内核 BLOCKED 表条目）。
    pub async fn prune_expired(&self) {
        let expired: Vec<IpAddr> = {
            let guard = self.blocked.lock().unwrap();
            let now = now_unix();
            guard
                .iter()
                .filter(|(_, e)| e.expire_unix.map(|t| t <= now).unwrap_or(false))
                .map(|(k, _)| *k)
                .collect()
        };
        if expired.is_empty() {
            return;
        }
        let mut handle = self.handle.lock().await;
        for key in expired {
            if handle.unblock(key).is_ok() {
                self.blocked.lock().unwrap().remove(&key);
                if let Some(p) = &self.persist {
                    if let Err(e) = p.delete_blocklist(&key) {
                        warn!("persist prune {} failed: {e:#}", key);
                    }
                }
                info!("expired block {}", key);
            }
        }
    }

    // ---- Suricata 规则（WebAPI 只收规则文本）----

    /// 当前全部 Suricata 规则。
    pub fn suri_rules_out(&self) -> Vec<SuricataRuleOut> {
        self.suricata_rules
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.to_out())
            .collect()
    }

    /// 全部 Suricata 规则文本（导出 .rules 文件用，一行一条）。
    pub fn export_suri_rules(&self) -> String {
        let list = self.suricata_rules.lock().unwrap();
        list.iter()
            .map(|r| r.suricata_str.clone())
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// 重同步 Suricata 规则头预过滤表（增删/恢复后调用）。
    pub async fn resync_suri_prefilter(&self) -> Result<()> {
        let rules = self.suricata_rules.lock().unwrap().clone();
        let mut tuples = crate::suricata_rules::SuriTuples::default();
        for r in &rules {
            let t = r.tuples();
            tuples.dst.extend(t.dst);
            tuples.dst_any.extend(t.dst_any);
            tuples.src.extend(t.src);
            tuples.src_any.extend(t.src_any);
        }
        let mut handle = self.handle.lock().await;
        handle.sync_suricata_rules(&tuples, self.suricata_prefilter.load(Ordering::Relaxed))
    }

    /// 新增一条 Suricata 规则：解析头部 → 持久化 → 重同步预过滤。
    pub async fn add_suri_rule(&self, text: &str) -> Result<SuricataRuleOut> {
        let parsed = crate::suricata_rules::parse_rule(text)?;
        let exp = crate::suricata_rules::expand_header(&parsed)?;
        let text = text.trim().to_string();
        if self
            .suricata_rules
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.suricata_str == text)
        {
            anyhow::bail!("suricata rule already exists");
        }
        let id = match &self.persist {
            Some(p) => p.insert_suricata_rule(&crate::persist::SuricataRuleRow {
                id: None,
                text: text.clone(),
                enabled: true,
            })? as u64,
            None => self.next_suri_rule_id.fetch_add(1, Ordering::Relaxed),
        };
        let rule = crate::suricata_rules::SuriRule {
            id,
            suricata_str: text,
            enabled: true,
            prefilter: !exp.tuples.is_empty(),
            prefilter_note: exp.note,
        };
        self.suricata_rules.lock().unwrap().push(rule.clone());
        self.resync_suri_prefilter().await?;
        info!("suricata rule added via API: id={id}");
        Ok(rule.to_out())
    }

    /// 批量导入 Suricata 规则（逐条；重复/非法条目计入 failed）。
    pub async fn import_suri_rules(&self, rules: Vec<String>) -> Result<SuricataRuleImportOut> {
        let total = rules.len();
        let mut added = 0usize;
        let mut failed = 0usize;
        let mut errors = Vec::new();
        for r in rules {
            let t = r.trim().to_string();
            if t.is_empty() {
                failed += 1;
                errors.push("empty rule".into());
                continue;
            }
            match self.add_suri_rule(&t).await {
                Ok(_) => added += 1,
                Err(e) => {
                    failed += 1;
                    errors.push(format!("{t}: {e}"));
                }
            }
        }
        Ok(SuricataRuleImportOut {
            total,
            added,
            failed,
            errors,
            rules: self.suri_rules_out(),
        })
    }

    /// 删除一条 Suricata 规则（按 id）。
    pub async fn delete_suri_rule(&self, id: u64) -> Result<bool> {
        let removed = {
            let mut list = self.suricata_rules.lock().unwrap();
            let before = list.len();
            list.retain(|r| r.id != id);
            list.len() != before
        };
        if !removed {
            return Ok(false);
        }
        if let Some(p) = &self.persist {
            p.delete_suricata_rule(id as i64)?;
        }
        self.resync_suri_prefilter().await?;
        info!("suricata rule deleted via API: id={id}");
        Ok(true)
    }

    /// 修改一条 Suricata 规则启停（PATCH）。返回更新后的规则（None=不存在）。
    pub async fn patch_suri_rule(
        &self,
        id: u64,
        enabled: Option<bool>,
    ) -> Result<Option<SuricataRuleOut>> {
        let exists = {
            let list = self.suricata_rules.lock().unwrap();
            list.iter().any(|r| r.id == id)
        };
        if !exists {
            return Ok(None);
        }
        if let Some(v) = enabled {
            if let Some(p) = &self.persist {
                p.patch_suricata_rule(id as i64, v)?;
            }
            let mut list = self.suricata_rules.lock().unwrap();
            if let Some(rule) = list.iter_mut().find(|r| r.id == id) {
                rule.enabled = v;
            }
        }
        self.resync_suri_prefilter().await?;
        Ok(self
            .suricata_rules
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.to_out()))
    }

    /// 原地更新一条 Suricata 规则文本（PUT）。返回更新后的规则（None=不存在）。
    pub async fn update_suri_rule(&self, id: u64, text: &str) -> Result<Option<SuricataRuleOut>> {
        let parsed = crate::suricata_rules::parse_rule(text)?;
        let exp = crate::suricata_rules::expand_header(&parsed)?;
        let text = text.trim().to_string();
        let exists = {
            let list = self.suricata_rules.lock().unwrap();
            list.iter().any(|r| r.id == id)
        };
        if !exists {
            return Ok(None);
        }
        if let Some(p) = &self.persist {
            p.update_suricata_rule(
                id as i64,
                &crate::persist::SuricataRuleRow {
                    id: Some(id as i64),
                    text: text.clone(),
                    enabled: true,
                },
            )?;
        }
        {
            let mut list = self.suricata_rules.lock().unwrap();
            if let Some(rule) = list.iter_mut().find(|r| r.id == id) {
                rule.suricata_str = text;
                rule.prefilter = !exp.tuples.is_empty();
                rule.prefilter_note = exp.note;
            }
        }
        self.resync_suri_prefilter().await?;
        Ok(self
            .suricata_rules
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.to_out()))
    }

    /// 批量删除 Suricata 规则，返回删除条数。
    pub async fn delete_suri_rules(&self, ids: &[u64]) -> Result<usize> {
        let removed = {
            let mut list = self.suricata_rules.lock().unwrap();
            let before = list.len();
            list.retain(|r| !ids.contains(&r.id));
            before - list.len()
        };
        if removed > 0 {
            let ids_i64: Vec<i64> = ids.iter().map(|i| *i as i64).collect();
            if let Some(p) = &self.persist {
                p.delete_suricata_rules(&ids_i64)?;
            }
            self.resync_suri_prefilter().await?;
        }
        Ok(removed)
    }

    // ---- QoS 分类（WebAPI 管理，热同步 QOS_CLASSES）----

    /// 当前全部 QoS 分类（API 输出）。
    pub fn qos_classes_out(&self) -> Vec<QosClassOut> {
        self.qos_classes
            .lock()
            .unwrap()
            .iter()
            .map(|r| qos_class_to_out(r))
            .collect()
    }

    /// 重同步 QoS 分类到 eBPF（增删改/恢复后调用）。
    pub async fn resync_qos(&self) -> Result<()> {
        let entries: Vec<k_firewall_common::maps::QosConfig> = self
            .qos_classes
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.enabled)
            .map(|r| qos_config_from_row(r, &self.interfaces))
            .collect();
        let mut handle = self.handle.lock().await;
        handle.sync_qos_classes(&entries)
    }

    /// 新增一个 QoS 分类：校验 → 持久化 → 内存 → 热同步。
    pub async fn add_qos_class(&self, req: &QosClassRequest) -> Result<QosClassOut> {
        validate_qos_class(
            &req.name,
            req.dscp,
            &req.proto,
            req.src_port,
            req.dst_port,
            &self.interfaces,
            &req.ingress_iface,
        )?;
        let (row, id) = {
            let mut list = self.qos_classes.lock().unwrap();
            if list.iter().any(|r| r.name == req.name) {
                anyhow::bail!("qos class {:?} already exists", req.name);
            }
            let mut row = crate::persist::QosClassRow {
                id: None,
                name: req.name.clone(),
                dscp: req.dscp,
                ingress_iface: req.ingress_iface.clone().unwrap_or_default(),
                proto: req.proto.clone(),
                src_port: req.src_port,
                dst_port: req.dst_port,
                rate_bps: req.rate_bps,
                burst_bytes: req.burst_bytes,
                enabled: true,
            };
            let id = match &self.persist {
                Some(p) => p.insert_qos_class(&row)?,
                None => self.next_qos_class_id.fetch_add(1, Ordering::Relaxed) as i64,
            };
            row.id = Some(id);
            list.push(row.clone());
            (row, id)
        };
        self.resync_qos().await?;
        info!("qos class added via API: id={id} name={}", req.name);
        Ok(qos_class_to_out(&row))
    }

    /// 原地替换一个 QoS 分类（PUT）。None = 不存在。
    pub async fn update_qos_class(
        &self,
        id: u64,
        req: &QosClassUpdateRequest,
    ) -> Result<Option<QosClassOut>> {
        validate_qos_class(
            &req.name,
            req.dscp,
            &req.proto,
            req.src_port,
            req.dst_port,
            &self.interfaces,
            &req.ingress_iface,
        )?;
        let row = {
            let mut list = self.qos_classes.lock().unwrap();
            let idx = match list.iter().position(|r| r.id == Some(id as i64)) {
                Some(i) => i,
                None => return Ok(None),
            };
            if list
                .iter()
                .enumerate()
                .any(|(i, r)| i != idx && r.name == req.name)
            {
                anyhow::bail!("qos class {:?} already exists", req.name);
            }
            let row = crate::persist::QosClassRow {
                id: Some(id as i64),
                name: req.name.clone(),
                dscp: req.dscp,
                ingress_iface: req.ingress_iface.clone().unwrap_or_default(),
                proto: req.proto.clone(),
                src_port: req.src_port,
                dst_port: req.dst_port,
                rate_bps: req.rate_bps,
                burst_bytes: req.burst_bytes,
                enabled: list[idx].enabled,
            };
            if let Some(p) = &self.persist {
                p.update_qos_class(id as i64, &row)?;
            }
            list[idx] = row.clone();
            row
        };
        self.resync_qos().await?;
        info!("qos class updated via API: id={id}");
        Ok(Some(qos_class_to_out(&row)))
    }

    /// 部分更新一个 QoS 分类（PATCH，启停）。None = 不存在。
    pub async fn patch_qos_class(
        &self,
        id: u64,
        enabled: Option<bool>,
    ) -> Result<Option<QosClassOut>> {
        let exists = {
            let list = self.qos_classes.lock().unwrap();
            list.iter().any(|r| r.id == Some(id as i64))
        };
        if !exists {
            return Ok(None);
        }
        if let Some(v) = enabled {
            if let Some(p) = &self.persist {
                p.patch_qos_class(id as i64, v)?;
            }
            let mut list = self.qos_classes.lock().unwrap();
            if let Some(r) = list.iter_mut().find(|r| r.id == Some(id as i64)) {
                r.enabled = v;
            }
        }
        self.resync_qos().await?;
        Ok(self
            .qos_classes
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == Some(id as i64))
            .map(qos_class_to_out))
    }

    /// 删除一个 QoS 分类（按 id）。
    pub async fn delete_qos_class(&self, id: u64) -> Result<bool> {
        let removed = {
            let mut list = self.qos_classes.lock().unwrap();
            let before = list.len();
            list.retain(|r| r.id != Some(id as i64));
            list.len() != before
        };
        if !removed {
            return Ok(false);
        }
        if let Some(p) = &self.persist {
            p.delete_qos_class(id as i64)?;
        }
        self.resync_qos().await?;
        info!("qos class deleted via API: id={id}");
        Ok(true)
    }

    /// 批量删除 QoS 分类，返回删除条数。
    pub async fn delete_qos_classes(&self, ids: &[u64]) -> Result<usize> {
        let removed = {
            let mut list = self.qos_classes.lock().unwrap();
            let before = list.len();
            list.retain(|r| !ids.contains(&(r.id.unwrap_or(0) as u64)));
            before - list.len()
        };
        if removed > 0 {
            let ids_i64: Vec<i64> = ids.iter().map(|i| *i as i64).collect();
            if let Some(p) = &self.persist {
                for id in ids_i64 {
                    p.delete_qos_class(id)?;
                }
            }
            self.resync_qos().await?;
        }
        Ok(removed)
    }

    // ---- 源 IP 速率限制（/security/rate-limits）----

    /// 当前全部速率限制规则。
    pub fn rate_limits_out(&self) -> Vec<RateLimitOut> {
        self.rate_limits
            .lock()
            .unwrap()
            .iter()
            .map(rate_limit_to_out)
            .collect()
    }

    /// 重同步速率限制表（增删改/交换后调用）。
    pub async fn resync_rate_limits(&self) -> Result<()> {
        let entries = {
            let list = self.rate_limits.lock().unwrap();
            rate_entries_from_rows(&list)
        };
        let mut handle = self.handle.lock().await;
        handle.sync_rate_limit_entries(&entries)
    }

    /// 新增一条速率限制规则（id 可自定）。校验 → 持久化 → 内存 → 热同步。
    pub async fn add_rate_limit(&self, req: &RateLimitRequest) -> Result<RateLimitOut> {
        let src_ip: IpAddr = req.src_ip.parse().map_err(|_| anyhow!("invalid src_ip"))?;
        if req.rate == 0 {
            anyhow::bail!("rate must be > 0");
        }
        if req.burst == 0 {
            anyhow::bail!("burst must be > 0");
        }
        let (row, id) = {
            let mut list = self.rate_limits.lock().unwrap();
            if list.iter().any(|r| r.src_ip == src_ip) {
                anyhow::bail!("rate limit for {src_ip} already exists");
            }
            let mut row = crate::persist::RateLimitRow {
                id: None,
                src_ip,
                rate: req.rate,
                burst: req.burst,
                enabled: true,
            };
            let custom = match req.id {
                Some(c) if c > 0 => {
                    if list.iter().any(|r| r.id == Some(c as i64)) {
                        anyhow::bail!("rate limit id {c} already in use");
                    }
                    c as i64
                }
                _ => 0,
            };
            if custom > 0 {
                row.id = Some(custom);
            }
            let id = match &self.persist {
                Some(p) => p.insert_rate_limit(&row)?,
                None => {
                    if custom > 0 {
                        custom
                    } else {
                        self.next_rate_limit_id.fetch_add(1, Ordering::Relaxed) as i64
                    }
                }
            };
            row.id = Some(id);
            list.push(row.clone());
            self.next_rate_limit_id
                .fetch_max(id as u64 + 1, Ordering::Relaxed);
            (row, id)
        };
        self.resync_rate_limits().await?;
        info!("rate limit added via API: id={id} src={}", row.src_ip);
        Ok(rate_limit_to_out(&row))
    }

    /// 原地替换一条速率限制规则（PUT）。None = 不存在。
    pub async fn update_rate_limit(
        &self,
        id: u64,
        req: &RateLimitUpdateRequest,
    ) -> Result<Option<RateLimitOut>> {
        let src_ip: IpAddr = req.src_ip.parse().map_err(|_| anyhow!("invalid src_ip"))?;
        if req.rate == 0 {
            anyhow::bail!("rate must be > 0");
        }
        if req.burst == 0 {
            anyhow::bail!("burst must be > 0");
        }
        let row = {
            let mut list = self.rate_limits.lock().unwrap();
            let idx = match list.iter().position(|r| r.id == Some(id as i64)) {
                Some(i) => i,
                None => return Ok(None),
            };
            if list
                .iter()
                .enumerate()
                .any(|(i, r)| i != idx && r.src_ip == src_ip)
            {
                anyhow::bail!("rate limit for {src_ip} already exists");
            }
            let row = crate::persist::RateLimitRow {
                id: Some(id as i64),
                src_ip,
                rate: req.rate,
                burst: req.burst,
                enabled: list[idx].enabled,
            };
            if let Some(p) = &self.persist {
                p.update_rate_limit(id as i64, &row)?;
            }
            list[idx] = row.clone();
            row
        };
        self.resync_rate_limits().await?;
        info!("rate limit updated via API: id={id}");
        Ok(Some(rate_limit_to_out(&row)))
    }

    /// 部分更新一条速率限制规则（PATCH，启停）。None = 不存在。
    pub async fn patch_rate_limit(
        &self,
        id: u64,
        enabled: Option<bool>,
    ) -> Result<Option<RateLimitOut>> {
        let exists = {
            let list = self.rate_limits.lock().unwrap();
            list.iter().any(|r| r.id == Some(id as i64))
        };
        if !exists {
            return Ok(None);
        }
        if let Some(v) = enabled {
            if let Some(p) = &self.persist {
                p.patch_rate_limit(id as i64, v)?;
            }
            let mut list = self.rate_limits.lock().unwrap();
            if let Some(r) = list.iter_mut().find(|r| r.id == Some(id as i64)) {
                r.enabled = v;
            }
        }
        self.resync_rate_limits().await?;
        Ok(self
            .rate_limits
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == Some(id as i64))
            .map(rate_limit_to_out))
    }

    /// 删除一条速率限制规则（按 id）。
    pub async fn delete_rate_limit(&self, id: u64) -> Result<bool> {
        let removed = {
            let mut list = self.rate_limits.lock().unwrap();
            let before = list.len();
            list.retain(|r| r.id != Some(id as i64));
            list.len() != before
        };
        if !removed {
            return Ok(false);
        }
        if let Some(p) = &self.persist {
            p.delete_rate_limit(id as i64)?;
        }
        self.resync_rate_limits().await?;
        info!("rate limit deleted via API: id={id}");
        Ok(true)
    }

    /// 批量删除速率限制规则，返回删除条数。
    pub async fn delete_rate_limits(&self, ids: &[u64]) -> Result<usize> {
        let removed = {
            let mut list = self.rate_limits.lock().unwrap();
            let before = list.len();
            list.retain(|r| !ids.contains(&(r.id.unwrap_or(0) as u64)));
            before - list.len()
        };
        if removed > 0 {
            let ids_i64: Vec<i64> = ids.iter().map(|i| *i as i64).collect();
            if let Some(p) = &self.persist {
                for id in ids_i64 {
                    p.delete_rate_limit(id)?;
                }
            }
            self.resync_rate_limits().await?;
        }
        Ok(removed)
    }

    /// 交换两条速率限制规则的执行顺序（互换 DB 行 id 后全量重同步）。
    pub async fn swap_rate_limits(
        &self,
        id_a: u64,
        id_b: u64,
    ) -> Result<Option<(RateLimitOut, RateLimitOut)>> {
        if id_a == id_b {
            return Ok(None);
        }
        match &self.persist {
            Some(p) => {
                if !p.swap_ids("rate_limit_rules", "id", id_a as i64, id_b as i64)? {
                    return Ok(None);
                }
                *self.rate_limits.lock().unwrap() = p.load_rate_limits()?;
            }
            None => {
                let mut list = self.rate_limits.lock().unwrap();
                let mut ia = None;
                let mut ib = None;
                for (i, r) in list.iter().enumerate() {
                    if r.id == Some(id_a as i64) {
                        ia = Some(i);
                    }
                    if r.id == Some(id_b as i64) {
                        ib = Some(i);
                    }
                }
                let (i_a, i_b) = match (ia, ib) {
                    (Some(a), Some(b)) => (a, b),
                    _ => return Ok(None),
                };
                let tmp = list[i_a].id;
                list[i_a].id = list[i_b].id;
                list[i_b].id = tmp;
            }
        }
        self.resync_rate_limits().await?;
        let list = self.rate_limits.lock().unwrap();
        let a = list.iter().find(|r| r.id == Some(id_a as i64));
        let b = list.iter().find(|r| r.id == Some(id_b as i64));
        match (a, b) {
            (Some(a), Some(b)) => Ok(Some((rate_limit_to_out(a), rate_limit_to_out(b)))),
            _ => Ok(None),
        }
    }

    // ---- 每源并发连接数限制（/security/conn-limits）----

    /// 当前全部并发连接数限制规则。
    pub fn conn_limits_out(&self) -> Vec<ConnLimitOut> {
        self.conn_limits
            .lock()
            .unwrap()
            .iter()
            .map(conn_limit_to_out)
            .collect()
    }

    /// 重同步并发连接数限制表。
    pub async fn resync_conn_limits(&self) -> Result<()> {
        let entries = {
            let list = self.conn_limits.lock().unwrap();
            conn_entries_from_rows(&list)
        };
        let mut handle = self.handle.lock().await;
        handle.sync_conn_limits(&entries)
    }

    /// 新增一条并发连接数限制规则（id 可自定）。
    pub async fn add_conn_limit(&self, req: &ConnLimitRequest) -> Result<ConnLimitOut> {
        let src_ip: IpAddr = req.src_ip.parse().map_err(|_| anyhow!("invalid src_ip"))?;
        if req.max_conns == 0 {
            anyhow::bail!("max_conns must be > 0");
        }
        let (row, id) = {
            let mut list = self.conn_limits.lock().unwrap();
            if list.iter().any(|r| r.src_ip == src_ip) {
                anyhow::bail!("conn limit for {src_ip} already exists");
            }
            let mut row = crate::persist::ConnLimitRow {
                id: None,
                src_ip,
                max_conns: req.max_conns,
                enabled: true,
            };
            let custom = match req.id {
                Some(c) if c > 0 => {
                    if list.iter().any(|r| r.id == Some(c as i64)) {
                        anyhow::bail!("conn limit id {c} already in use");
                    }
                    c as i64
                }
                _ => 0,
            };
            if custom > 0 {
                row.id = Some(custom);
            }
            let id = match &self.persist {
                Some(p) => p.insert_conn_limit(&row)?,
                None => {
                    if custom > 0 {
                        custom
                    } else {
                        self.next_conn_limit_id.fetch_add(1, Ordering::Relaxed) as i64
                    }
                }
            };
            row.id = Some(id);
            list.push(row.clone());
            self.next_conn_limit_id
                .fetch_max(id as u64 + 1, Ordering::Relaxed);
            (row, id)
        };
        self.resync_conn_limits().await?;
        info!("conn limit added via API: id={id} src={}", row.src_ip);
        Ok(conn_limit_to_out(&row))
    }

    /// 原地替换一条并发连接数限制规则（PUT）。None = 不存在。
    pub async fn update_conn_limit(
        &self,
        id: u64,
        req: &ConnLimitUpdateRequest,
    ) -> Result<Option<ConnLimitOut>> {
        let src_ip: IpAddr = req.src_ip.parse().map_err(|_| anyhow!("invalid src_ip"))?;
        if req.max_conns == 0 {
            anyhow::bail!("max_conns must be > 0");
        }
        let row = {
            let mut list = self.conn_limits.lock().unwrap();
            let idx = match list.iter().position(|r| r.id == Some(id as i64)) {
                Some(i) => i,
                None => return Ok(None),
            };
            if list
                .iter()
                .enumerate()
                .any(|(i, r)| i != idx && r.src_ip == src_ip)
            {
                anyhow::bail!("conn limit for {src_ip} already exists");
            }
            let row = crate::persist::ConnLimitRow {
                id: Some(id as i64),
                src_ip,
                max_conns: req.max_conns,
                enabled: list[idx].enabled,
            };
            if let Some(p) = &self.persist {
                p.update_conn_limit(id as i64, &row)?;
            }
            list[idx] = row.clone();
            row
        };
        self.resync_conn_limits().await?;
        info!("conn limit updated via API: id={id}");
        Ok(Some(conn_limit_to_out(&row)))
    }

    /// 部分更新一条并发连接数限制规则（PATCH，启停）。None = 不存在。
    pub async fn patch_conn_limit(
        &self,
        id: u64,
        enabled: Option<bool>,
    ) -> Result<Option<ConnLimitOut>> {
        let exists = {
            let list = self.conn_limits.lock().unwrap();
            list.iter().any(|r| r.id == Some(id as i64))
        };
        if !exists {
            return Ok(None);
        }
        if let Some(v) = enabled {
            if let Some(p) = &self.persist {
                p.patch_conn_limit(id as i64, v)?;
            }
            let mut list = self.conn_limits.lock().unwrap();
            if let Some(r) = list.iter_mut().find(|r| r.id == Some(id as i64)) {
                r.enabled = v;
            }
        }
        self.resync_conn_limits().await?;
        Ok(self
            .conn_limits
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == Some(id as i64))
            .map(conn_limit_to_out))
    }

    /// 删除一条并发连接数限制规则（按 id）。
    pub async fn delete_conn_limit(&self, id: u64) -> Result<bool> {
        let removed = {
            let mut list = self.conn_limits.lock().unwrap();
            let before = list.len();
            list.retain(|r| r.id != Some(id as i64));
            list.len() != before
        };
        if !removed {
            return Ok(false);
        }
        if let Some(p) = &self.persist {
            p.delete_conn_limit(id as i64)?;
        }
        self.resync_conn_limits().await?;
        info!("conn limit deleted via API: id={id}");
        Ok(true)
    }

    /// 批量删除并发连接数限制规则，返回删除条数。
    pub async fn delete_conn_limits(&self, ids: &[u64]) -> Result<usize> {
        let removed = {
            let mut list = self.conn_limits.lock().unwrap();
            let before = list.len();
            list.retain(|r| !ids.contains(&(r.id.unwrap_or(0) as u64)));
            before - list.len()
        };
        if removed > 0 {
            let ids_i64: Vec<i64> = ids.iter().map(|i| *i as i64).collect();
            if let Some(p) = &self.persist {
                for id in ids_i64 {
                    p.delete_conn_limit(id)?;
                }
            }
            self.resync_conn_limits().await?;
        }
        Ok(removed)
    }

    /// 交换两条并发连接数限制规则的执行顺序。
    pub async fn swap_conn_limits(
        &self,
        id_a: u64,
        id_b: u64,
    ) -> Result<Option<(ConnLimitOut, ConnLimitOut)>> {
        if id_a == id_b {
            return Ok(None);
        }
        match &self.persist {
            Some(p) => {
                if !p.swap_ids("conn_limit_rules", "id", id_a as i64, id_b as i64)? {
                    return Ok(None);
                }
                *self.conn_limits.lock().unwrap() = p.load_conn_limits()?;
            }
            None => {
                let mut list = self.conn_limits.lock().unwrap();
                let mut ia = None;
                let mut ib = None;
                for (i, r) in list.iter().enumerate() {
                    if r.id == Some(id_a as i64) {
                        ia = Some(i);
                    }
                    if r.id == Some(id_b as i64) {
                        ib = Some(i);
                    }
                }
                let (i_a, i_b) = match (ia, ib) {
                    (Some(a), Some(b)) => (a, b),
                    _ => return Ok(None),
                };
                let tmp = list[i_a].id;
                list[i_a].id = list[i_b].id;
                list[i_b].id = tmp;
            }
        }
        self.resync_conn_limits().await?;
        let list = self.conn_limits.lock().unwrap();
        let a = list.iter().find(|r| r.id == Some(id_a as i64));
        let b = list.iter().find(|r| r.id == Some(id_b as i64));
        match (a, b) {
            (Some(a), Some(b)) => Ok(Some((conn_limit_to_out(a), conn_limit_to_out(b)))),
            _ => Ok(None),
        }
    }

    // ---- NAT 端口转发（/nat/rules）----

    /// 当前全部 NAT 规则。
    pub fn nat_rules_out(&self) -> Vec<NatRuleOut> {
        self.nat_rules
            .lock()
            .unwrap()
            .iter()
            .map(nat_rule_to_out)
            .collect()
    }

    /// 重同步 DNAT 规则表。
    pub async fn resync_nat_rules(&self) -> Result<()> {
        let entries = {
            let list = self.nat_rules.lock().unwrap();
            nat_entries_from_rows(&list, &self.interfaces)
        };
        let mut handle = self.handle.lock().await;
        handle.sync_dnat_rules(&entries)
    }

    /// 新增一条 NAT 规则（id 可自定）。
    pub async fn add_nat_rule(&self, req: &NatRuleRequest) -> Result<NatRuleOut> {
        let dst_ip: Ipv4Addr = req.dst_ip.parse().map_err(|_| anyhow!("invalid dst_ip"))?;
        let to_ip: Ipv4Addr = req.to_ip.parse().map_err(|_| anyhow!("invalid to_ip"))?;
        if req.dst_port == 0 || req.to_port == 0 {
            anyhow::bail!("dst_port/to_port must be nonzero");
        }
        let proto = match req.proto.as_str() {
            "tcp" | "udp" => req.proto.clone(),
            other => anyhow::bail!("unsupported proto {other:?} (tcp|udp)"),
        };
        let (row, id) = {
            let mut list = self.nat_rules.lock().unwrap();
            if list
                .iter()
                .any(|r| r.dst_ip == dst_ip && r.dst_port == req.dst_port && r.proto == proto)
            {
                anyhow::bail!("nat rule for {dst_ip}:{} {} already exists", req.dst_port, proto);
            }
            let mut row = crate::persist::NatRuleRow {
                id: None,
                dst_ip,
                dst_port: req.dst_port,
                proto,
                to_ip,
                to_port: req.to_port,
                enabled: true,
            };
            let custom = match req.id {
                Some(c) if c > 0 => {
                    if list.iter().any(|r| r.id == Some(c as i64)) {
                        anyhow::bail!("nat rule id {c} already in use");
                    }
                    c as i64
                }
                _ => 0,
            };
            if custom > 0 {
                row.id = Some(custom);
            }
            let id = match &self.persist {
                Some(p) => p.insert_nat_rule(&row)?,
                None => {
                    if custom > 0 {
                        custom
                    } else {
                        self.next_nat_rule_id.fetch_add(1, Ordering::Relaxed) as i64
                    }
                }
            };
            row.id = Some(id);
            list.push(row.clone());
            self.next_nat_rule_id
                .fetch_max(id as u64 + 1, Ordering::Relaxed);
            (row, id)
        };
        self.resync_nat_rules().await?;
        info!("nat rule added via API: id={id} {}:{}/{} -> {}:{}", row.dst_ip, row.dst_port, row.proto, row.to_ip, row.to_port);
        Ok(nat_rule_to_out(&row))
    }

    /// 原地替换一条 NAT 规则（PUT）。None = 不存在。
    pub async fn update_nat_rule(
        &self,
        id: u64,
        req: &NatRuleUpdateRequest,
    ) -> Result<Option<NatRuleOut>> {
        let dst_ip: Ipv4Addr = req.dst_ip.parse().map_err(|_| anyhow!("invalid dst_ip"))?;
        let to_ip: Ipv4Addr = req.to_ip.parse().map_err(|_| anyhow!("invalid to_ip"))?;
        if req.dst_port == 0 || req.to_port == 0 {
            anyhow::bail!("dst_port/to_port must be nonzero");
        }
        let proto = match req.proto.as_str() {
            "tcp" | "udp" => req.proto.clone(),
            other => anyhow::bail!("unsupported proto {other:?} (tcp|udp)"),
        };
        let row = {
            let mut list = self.nat_rules.lock().unwrap();
            let idx = match list.iter().position(|r| r.id == Some(id as i64)) {
                Some(i) => i,
                None => return Ok(None),
            };
            let row = crate::persist::NatRuleRow {
                id: Some(id as i64),
                dst_ip,
                dst_port: req.dst_port,
                proto,
                to_ip,
                to_port: req.to_port,
                enabled: list[idx].enabled,
            };
            if let Some(p) = &self.persist {
                p.update_nat_rule(id as i64, &row)?;
            }
            list[idx] = row.clone();
            row
        };
        self.resync_nat_rules().await?;
        info!("nat rule updated via API: id={id}");
        Ok(Some(nat_rule_to_out(&row)))
    }

    /// 部分更新一条 NAT 规则（PATCH，启停）。None = 不存在。
    pub async fn patch_nat_rule(
        &self,
        id: u64,
        enabled: Option<bool>,
    ) -> Result<Option<NatRuleOut>> {
        let exists = {
            let list = self.nat_rules.lock().unwrap();
            list.iter().any(|r| r.id == Some(id as i64))
        };
        if !exists {
            return Ok(None);
        }
        if let Some(v) = enabled {
            if let Some(p) = &self.persist {
                p.patch_nat_rule(id as i64, v)?;
            }
            let mut list = self.nat_rules.lock().unwrap();
            if let Some(r) = list.iter_mut().find(|r| r.id == Some(id as i64)) {
                r.enabled = v;
            }
        }
        self.resync_nat_rules().await?;
        Ok(self
            .nat_rules
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == Some(id as i64))
            .map(nat_rule_to_out))
    }

    /// 删除一条 NAT 规则（按 id）。
    pub async fn delete_nat_rule(&self, id: u64) -> Result<bool> {
        let removed = {
            let mut list = self.nat_rules.lock().unwrap();
            let before = list.len();
            list.retain(|r| r.id != Some(id as i64));
            list.len() != before
        };
        if !removed {
            return Ok(false);
        }
        if let Some(p) = &self.persist {
            p.delete_nat_rule(id as i64)?;
        }
        self.resync_nat_rules().await?;
        info!("nat rule deleted via API: id={id}");
        Ok(true)
    }

    /// 批量删除 NAT 规则，返回删除条数。
    pub async fn delete_nat_rules(&self, ids: &[u64]) -> Result<usize> {
        let removed = {
            let mut list = self.nat_rules.lock().unwrap();
            let before = list.len();
            list.retain(|r| !ids.contains(&(r.id.unwrap_or(0) as u64)));
            before - list.len()
        };
        if removed > 0 {
            let ids_i64: Vec<i64> = ids.iter().map(|i| *i as i64).collect();
            if let Some(p) = &self.persist {
                for id in ids_i64 {
                    p.delete_nat_rule(id)?;
                }
            }
            self.resync_nat_rules().await?;
        }
        Ok(removed)
    }

    /// 交换两条 NAT 规则的执行顺序。
    pub async fn swap_nat_rules(
        &self,
        id_a: u64,
        id_b: u64,
    ) -> Result<Option<(NatRuleOut, NatRuleOut)>> {
        if id_a == id_b {
            return Ok(None);
        }
        match &self.persist {
            Some(p) => {
                if !p.swap_ids("nat_rules", "id", id_a as i64, id_b as i64)? {
                    return Ok(None);
                }
                *self.nat_rules.lock().unwrap() = p.load_nat_rules()?;
            }
            None => {
                let mut list = self.nat_rules.lock().unwrap();
                let mut ia = None;
                let mut ib = None;
                for (i, r) in list.iter().enumerate() {
                    if r.id == Some(id_a as i64) {
                        ia = Some(i);
                    }
                    if r.id == Some(id_b as i64) {
                        ib = Some(i);
                    }
                }
                let (i_a, i_b) = match (ia, ib) {
                    (Some(a), Some(b)) => (a, b),
                    _ => return Ok(None),
                };
                let tmp = list[i_a].id;
                list[i_a].id = list[i_b].id;
                list[i_b].id = tmp;
            }
        }
        self.resync_nat_rules().await?;
        let list = self.nat_rules.lock().unwrap();
        let a = list.iter().find(|r| r.id == Some(id_a as i64));
        let b = list.iter().find(|r| r.id == Some(id_b as i64));
        match (a, b) {
            (Some(a), Some(b)) => Ok(Some((nat_rule_to_out(a), nat_rule_to_out(b)))),
            _ => Ok(None),
        }
    }

    // ---- Zone 策略（/zones）----

    /// 当前全部 Zone 策略（id 升序）。
    pub fn zone_policies_out(&self) -> Vec<ZonePolicyOut> {
        self.zone_policies
            .lock()
            .unwrap()
            .iter()
            .map(zone_policy_to_out)
            .collect()
    }

    /// 重同步 Zone 策略表。
    pub async fn resync_zone_policies(&self) -> Result<()> {
        let entries = {
            let list = self.zone_policies.lock().unwrap();
            zone_entries_from_rows(&list, &self.interfaces)
        };
        let mut handle = self.handle.lock().await;
        handle.sync_zone_policies(&entries)
    }

    /// 新增一条 Zone 策略（id 可自定）。
    pub async fn add_zone_policy(&self, req: &ZonePolicyRequest) -> Result<ZonePolicyOut> {
        validate_zone_policy(&req.src_interface, &req.dst_interface, &req.action, &self.interfaces)?;
        let (row, id) = {
            let mut list = self.zone_policies.lock().unwrap();
            let mut row = crate::persist::ZonePolicyRow {
                id: None,
                src_interface: req.src_interface.clone(),
                dst_interface: req.dst_interface.clone(),
                action: req.action.clone(),
                enabled: true,
            };
            let custom = match req.id {
                Some(c) if c > 0 => {
                    if list.iter().any(|r| r.id == Some(c as i64)) {
                        anyhow::bail!("zone policy id {c} already in use");
                    }
                    c as i64
                }
                _ => 0,
            };
            if custom > 0 {
                row.id = Some(custom);
            }
            let id = match &self.persist {
                Some(p) => p.insert_zone_policy(&row)?,
                None => {
                    if custom > 0 {
                        custom
                    } else {
                        self.next_zone_policy_id.fetch_add(1, Ordering::Relaxed) as i64
                    }
                }
            };
            row.id = Some(id);
            list.push(row.clone());
            self.next_zone_policy_id
                .fetch_max(id as u64 + 1, Ordering::Relaxed);
            (row, id)
        };
        self.resync_zone_policies().await?;
        info!(
            "zone policy added via API: id={id} {} -> {} {}",
            row.src_interface, row.dst_interface, row.action
        );
        Ok(zone_policy_to_out(&row))
    }

    /// 原地替换一条 Zone 策略（PUT）。None = 不存在。
    pub async fn update_zone_policy(
        &self,
        id: u64,
        req: &ZonePolicyUpdateRequest,
    ) -> Result<Option<ZonePolicyOut>> {
        validate_zone_policy(&req.src_interface, &req.dst_interface, &req.action, &self.interfaces)?;
        let row = {
            let mut list = self.zone_policies.lock().unwrap();
            let idx = match list.iter().position(|r| r.id == Some(id as i64)) {
                Some(i) => i,
                None => return Ok(None),
            };
            let row = crate::persist::ZonePolicyRow {
                id: Some(id as i64),
                src_interface: req.src_interface.clone(),
                dst_interface: req.dst_interface.clone(),
                action: req.action.clone(),
                enabled: list[idx].enabled,
            };
            if let Some(p) = &self.persist {
                p.update_zone_policy(id as i64, &row)?;
            }
            list[idx] = row.clone();
            row
        };
        self.resync_zone_policies().await?;
        info!("zone policy updated via API: id={id}");
        Ok(Some(zone_policy_to_out(&row)))
    }

    /// 部分更新一条 Zone 策略（PATCH，启停）。None = 不存在。
    pub async fn patch_zone_policy(
        &self,
        id: u64,
        enabled: Option<bool>,
    ) -> Result<Option<ZonePolicyOut>> {
        let exists = {
            let list = self.zone_policies.lock().unwrap();
            list.iter().any(|r| r.id == Some(id as i64))
        };
        if !exists {
            return Ok(None);
        }
        if let Some(v) = enabled {
            if let Some(p) = &self.persist {
                p.patch_zone_policy(id as i64, v)?;
            }
            let mut list = self.zone_policies.lock().unwrap();
            if let Some(r) = list.iter_mut().find(|r| r.id == Some(id as i64)) {
                r.enabled = v;
            }
        }
        self.resync_zone_policies().await?;
        Ok(self
            .zone_policies
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == Some(id as i64))
            .map(zone_policy_to_out))
    }

    /// 删除一条 Zone 策略（按 id）。
    pub async fn delete_zone_policy(&self, id: u64) -> Result<bool> {
        let removed = {
            let mut list = self.zone_policies.lock().unwrap();
            let before = list.len();
            list.retain(|r| r.id != Some(id as i64));
            list.len() != before
        };
        if !removed {
            return Ok(false);
        }
        if let Some(p) = &self.persist {
            p.delete_zone_policy(id as i64)?;
        }
        self.resync_zone_policies().await?;
        info!("zone policy deleted via API: id={id}");
        Ok(true)
    }

    /// 批量删除 Zone 策略，返回删除条数。
    pub async fn delete_zone_policies(&self, ids: &[u64]) -> Result<usize> {
        let removed = {
            let mut list = self.zone_policies.lock().unwrap();
            let before = list.len();
            list.retain(|r| !ids.contains(&(r.id.unwrap_or(0) as u64)));
            before - list.len()
        };
        if removed > 0 {
            let ids_i64: Vec<i64> = ids.iter().map(|i| *i as i64).collect();
            if let Some(p) = &self.persist {
                for id in ids_i64 {
                    p.delete_zone_policy(id)?;
                }
            }
            self.resync_zone_policies().await?;
        }
        Ok(removed)
    }

    /// 交换两条 Zone 策略的执行顺序。
    pub async fn swap_zone_policies(
        &self,
        id_a: u64,
        id_b: u64,
    ) -> Result<Option<(ZonePolicyOut, ZonePolicyOut)>> {
        if id_a == id_b {
            return Ok(None);
        }
        match &self.persist {
            Some(p) => {
                if !p.swap_ids("zone_policies", "id", id_a as i64, id_b as i64)? {
                    return Ok(None);
                }
                *self.zone_policies.lock().unwrap() = p.load_zone_policies()?;
            }
            None => {
                let mut list = self.zone_policies.lock().unwrap();
                let mut ia = None;
                let mut ib = None;
                for (i, r) in list.iter().enumerate() {
                    if r.id == Some(id_a as i64) {
                        ia = Some(i);
                    }
                    if r.id == Some(id_b as i64) {
                        ib = Some(i);
                    }
                }
                let (i_a, i_b) = match (ia, ib) {
                    (Some(a), Some(b)) => (a, b),
                    _ => return Ok(None),
                };
                let tmp = list[i_a].id;
                list[i_a].id = list[i_b].id;
                list[i_b].id = tmp;
            }
        }
        self.resync_zone_policies().await?;
        let list = self.zone_policies.lock().unwrap();
        let a = list.iter().find(|r| r.id == Some(id_a as i64));
        let b = list.iter().find(|r| r.id == Some(id_b as i64));
        match (a, b) {
            (Some(a), Some(b)) => Ok(Some((zone_policy_to_out(a), zone_policy_to_out(b)))),
            _ => Ok(None),
        }
    }

    // ---- SYN Flood 防护（/security/syn-flood）----

    /// 当前 SYN Flood 防护配置。
    pub fn syn_flood_out(&self) -> SynFloodOut {
        let row = self.syn_flood.lock().unwrap();
        SynFloodOut {
            rate_pps: row.rate_pps,
            burst: row.burst,
            max_half_open: row.max_half_open,
        }
    }

    /// 整体替换 SYN Flood 防护配置并热同步 eBPF。
    pub async fn update_syn_flood(&self, req: &SynFloodRequest) -> Result<SynFloodOut> {
        if req.rate_pps > 4_000_000_000 {
            anyhow::bail!("rate_pps too large");
        }
        if req.burst == 0 && req.rate_pps > 0 {
            anyhow::bail!("burst must be > 0 when rate_pps enabled");
        }
        let row = crate::persist::SynFloodRow {
            rate_pps: req.rate_pps,
            burst: req.burst,
            max_half_open: req.max_half_open,
        };
        if let Some(p) = &self.persist {
            p.save_syn_flood(&row)?;
        }
        {
            let mut guard = self.syn_flood.lock().unwrap();
            *guard = row.clone();
        }
        let mut handle = self.handle.lock().await;
        handle.sync_syn_flood(row.rate_pps, row.burst, row.max_half_open)?;
        info!(
            "syn_flood updated via API: rate={} burst={} half_open={}",
            row.rate_pps, row.burst, row.max_half_open
        );
        Ok(SynFloodOut {
            rate_pps: row.rate_pps,
            burst: row.burst,
            max_half_open: row.max_half_open,
        })
    }
}

// ---- QoS 辅助函数 ----

/// 由运行时 QoS 行 + 接口列表推导 eBPF `QosConfig`（与配置加载路径一致：
/// 入向接口解析为物理 ifindex，端口转网络序，rate 上限 u32）。
fn qos_config_from_row(
    row: &crate::persist::QosClassRow,
    interfaces: &[crate::config::InterfaceConfig],
) -> k_firewall_common::maps::QosConfig {
    let ingress_ifindex = if row.ingress_iface.is_empty() {
        0
    } else {
        interfaces
            .iter()
            .find(|i| i.name == row.ingress_iface)
            .and_then(|i| {
                std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", i.phy_name())).ok()
            })
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0)
    };
    let proto = match row.proto.as_str() {
        "tcp" => 6,
        "udp" => 17,
        "icmp" => 1,
        "icmp6" | "icmpv6" => 58,
        _ => 0,
    };
    k_firewall_common::maps::QosConfig {
        ingress_ifindex,
        proto,
        _pad: [0; 3],
        src_port: row.src_port.to_be(),
        dst_port: row.dst_port.to_be(),
        dscp: row.dscp,
        _pad2: [0; 3],
        rate_bps: row.rate_bps.min(u32::MAX as u64) as u32,
        burst_bytes: row.burst_bytes,
    }
}

/// 运行时 QoS 行 → API 输出。
fn qos_class_to_out(row: &crate::persist::QosClassRow) -> QosClassOut {
    QosClassOut {
        id: row.id.unwrap_or(0) as u64,
        name: row.name.clone(),
        dscp: row.dscp,
        ingress_iface: if row.ingress_iface.is_empty() {
            None
        } else {
            Some(row.ingress_iface.clone())
        },
        proto: row.proto.clone(),
        src_port: row.src_port,
        dst_port: row.dst_port,
        rate_bps: row.rate_bps,
        burst_bytes: row.burst_bytes,
        enabled: row.enabled,
    }
}

// ---- 运行时规则集合辅助函数 ----

/// 运行时 NAT 规则行（按 id 升序、启用）→ eBPF `(DnatKey, DnatValue)` 条目。
fn nat_entries_from_rows(
    rows: &[crate::persist::NatRuleRow],
    _interfaces: &[crate::config::InterfaceConfig],
) -> Vec<(DnatKey, DnatValue)> {
    rows.iter()
        .filter(|r| r.enabled)
        .map(|r| {
            let proto = match r.proto.as_str() {
                "udp" => 17,
                _ => 6,
            };
            let key = DnatKey::from_ipv4(u32::from(r.dst_ip), r.dst_port.to_be(), proto);
            let value = DnatValue::from_ipv4(u32::from(r.to_ip), r.to_port.to_be());
            (key, value)
        })
        .collect()
}

/// 运行时速率限制行（启用）→ eBPF `(IpKey, rate, burst)` 条目。
fn rate_entries_from_rows(rows: &[crate::persist::RateLimitRow]) -> Vec<(IpKey, u32, u32)> {
    rows.iter()
        .filter(|r| r.enabled)
        .map(|r| {
            let key = match r.src_ip {
                IpAddr::V4(a) => IpKey::from_ipv4(u32::from(a)),
                IpAddr::V6(a) => IpKey::from_ipv6(a.octets()),
            };
            (key, r.rate, r.burst)
        })
        .collect()
}

/// 运行时并发连接数限制行（启用）→ eBPF `(IpKey, max_conns)` 条目。
fn conn_entries_from_rows(rows: &[crate::persist::ConnLimitRow]) -> Vec<(IpKey, u32)> {
    rows.iter()
        .filter(|r| r.enabled)
        .map(|r| {
            let key = match r.src_ip {
                IpAddr::V4(a) => IpKey::from_ipv4(u32::from(a)),
                IpAddr::V6(a) => IpKey::from_ipv6(a.octets()),
            };
            (key, r.max_conns)
        })
        .collect()
}

/// 运行时 Zone 策略行（按 id 升序、启用）→ eBPF `ZoneEntry` 条目。
///
/// 与配置 `zone_entries()` 语义一致：每条策略生成 src→dst 网段与 dst→src 网段
/// 两条双向条目，eBPF 按数组顺序（即 id 顺序）首匹配生效。
fn zone_entries_from_rows(
    rows: &[crate::persist::ZonePolicyRow],
    interfaces: &[crate::config::InterfaceConfig],
) -> Vec<ZoneEntry> {
    let mut out = Vec::new();
    for z in rows.iter().filter(|r| r.enabled) {
        let Some(src) = interfaces.iter().find(|i| &i.name == &z.src_interface) else {
            continue;
        };
        let Some(dst) = interfaces.iter().find(|i| &i.name == &z.dst_interface) else {
            continue;
        };
        let action = match z.action.as_str() {
            "drop" => k_firewall_common::ACTION_DROP,
            _ => k_firewall_common::ACTION_PASS,
        };
        let (src_net, src_prefix) = match src.address {
            Some(addr) => {
                let mask = src.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
                (u32::from(addr) & u32::from(mask), crate::config::mask_bits(mask))
            }
            None => (0u32, 0u32),
        };
        let (dst_net, dst_prefix) = match dst.address {
            Some(addr) => {
                let mask = dst.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
                (u32::from(addr) & u32::from(mask), crate::config::mask_bits(mask))
            }
            None => (0u32, 0u32),
        };
        let src_idx = crate::ebpf_loader::if_index(&src.phy_name()).unwrap_or(0) as u32;
        let dst_idx = crate::ebpf_loader::if_index(&dst.phy_name()).unwrap_or(0) as u32;
        out.push(ZoneEntry::from_ipv4(src_idx, dst_net, dst_prefix as u8, action));
        out.push(ZoneEntry::from_ipv4(dst_idx, src_net, src_prefix as u8, action));
    }
    out
}

/// 运行时 NAT 规则行 → API 输出。
fn nat_rule_to_out(row: &crate::persist::NatRuleRow) -> NatRuleOut {
    NatRuleOut {
        id: row.id.unwrap_or(0) as u64,
        dst_ip: row.dst_ip.to_string(),
        dst_port: row.dst_port,
        proto: row.proto.clone(),
        to_ip: row.to_ip.to_string(),
        to_port: row.to_port,
        enabled: row.enabled,
    }
}

/// 运行时速率限制行 → API 输出。
fn rate_limit_to_out(row: &crate::persist::RateLimitRow) -> RateLimitOut {
    RateLimitOut {
        id: row.id.unwrap_or(0) as u64,
        src_ip: row.src_ip.to_string(),
        rate: row.rate,
        burst: row.burst,
        enabled: row.enabled,
    }
}

/// 运行时并发连接数限制行 → API 输出。
fn conn_limit_to_out(row: &crate::persist::ConnLimitRow) -> ConnLimitOut {
    ConnLimitOut {
        id: row.id.unwrap_or(0) as u64,
        src_ip: row.src_ip.to_string(),
        max_conns: row.max_conns,
        enabled: row.enabled,
    }
}

/// 运行时 Zone 策略行 → API 输出。
fn zone_policy_to_out(row: &crate::persist::ZonePolicyRow) -> ZonePolicyOut {
    ZonePolicyOut {
        id: row.id.unwrap_or(0) as u64,
        src_interface: row.src_interface.clone(),
        dst_interface: row.dst_interface.clone(),
        action: row.action.clone(),
        enabled: row.enabled,
    }
}

/// 校验 QoS 分类字段（与配置加载路径一致）。
fn validate_qos_class(
    name: &str,
    dscp: u8,
    proto: &str,
    _src_port: u16,
    _dst_port: u16,
    interfaces: &[crate::config::InterfaceConfig],
    ingress_iface: &Option<String>,
) -> Result<()> {
    if name.is_empty() {
        anyhow::bail!("name is required");
    }
    if dscp > 63 {
        anyhow::bail!("dscp out of range 0..63");
    }
    match proto {
        "tcp" | "udp" | "icmp" | "icmp6" | "icmpv6" | "any" | "" => {}
        other => anyhow::bail!("unsupported proto {other:?} (tcp|udp|icmp|icmp6|any)"),
    }
    if let Some(iface) = ingress_iface {
        if !iface.is_empty() && !interfaces.iter().any(|i| i.name == *iface) {
            anyhow::bail!("unknown ingress_iface {iface:?}");
        }
    }
    Ok(())
}

/// 校验 Zone 策略字段（与配置加载路径一致）。
fn validate_zone_policy(
    src_interface: &str,
    dst_interface: &str,
    action: &str,
    interfaces: &[crate::config::InterfaceConfig],
) -> Result<()> {
    if !interfaces.iter().any(|i| i.name == src_interface) {
        anyhow::bail!("unknown src_interface {src_interface:?}");
    }
    if !interfaces.iter().any(|i| i.name == dst_interface) {
        anyhow::bail!("unknown dst_interface {dst_interface:?}");
    }
    match action {
        "accept" | "drop" => {}
        other => anyhow::bail!("unsupported action {other:?} (accept|drop)"),
    }
    Ok(())
}

/// 持久化数据库路径（日志用）。
fn p_path(config: &Config) -> String {
    config
        .daemon
        .db_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

fn status_inner(s: &AppState) -> Status {
    Status {
        iface: s.iface.clone(),
        attached: true,
        rule_count: s.suricata_rules.lock().unwrap().len() as u64,
        blocked_count: s.blocked.lock().unwrap().len() as u64,
        uptime_secs: SystemTime::now()
            .duration_since(s.started)
            .unwrap_or_default()
            .as_secs(),
    }
}

async fn status(State(s): State<Arc<AppState>>) -> Json<Status> {
    Json(status_inner(&s))
}

async fn get_stats(State(s): State<Arc<AppState>>) -> Result<Json<StatsOut>, ApiError> {
    let st = s.read_stats().await?;
    Ok(Json(StatsOut::from(st)))
}

/// GET /metrics：Prometheus text 格式（未认证，供抓取器使用）。
async fn metrics(State(s): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let st = s.read_stats().await?;
    let status = status_inner(&s);
    let sessions = s
        .handle
        .lock()
        .await
        .dump_sessions()
        .map(|v| v.len())
        .unwrap_or(0);
    let body = format!(
        "# HELP kfw_packets_total Total packets processed by XDP.\n\
         # TYPE kfw_packets_total counter\n\
         kfw_packets_total {}\n\
         # HELP kfw_passed_total Packets passed.\n\
         # TYPE kfw_passed_total counter\n\
         kfw_passed_total {}\n\
         # HELP kfw_dropped_total Packets dropped.\n\
         # TYPE kfw_dropped_total counter\n\
         kfw_dropped_total {}\n\
         # HELP kfw_blocked_total Packets blocked (including conntrack drop).\n\
         # TYPE kfw_blocked_total counter\n\
         kfw_blocked_total {}\n\
         # HELP kfw_suricata_rules Number of suricata rules loaded.\n\
         # TYPE kfw_suricata_rules gauge\n\
         kfw_suricata_rules {}\n\
         # HELP kfw_blocked_ips Number of IPs currently blocked.\n\
         # TYPE kfw_blocked_ips gauge\n\
         kfw_blocked_ips {}\n\
         # HELP kfw_active_sessions Number of conntrack sessions.\n\
         # TYPE kfw_active_sessions gauge\n\
         kfw_active_sessions {}\n\
         # HELP kfw_uptime_seconds Daemon uptime.\n\
         # TYPE kfw_uptime_seconds gauge\n\
         kfw_uptime_seconds {}\n",
        st.packets,
        st.passed,
        st.dropped,
        st.blocked,
        status.rule_count,
        status.blocked_count,
        sessions,
        status.uptime_secs,
    );
    Ok(Response::builder()
        .header(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")
        .body(Body::from(body))
        .expect("static metrics response"))
}

/// GET /api/v1/operational/events：SSE 事件流。
async fn sse_events(
    State(s): State<Arc<AppState>>,
) -> axum::response::Sse<
    impl futures_core::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    let rx = s.event_tx.subscribe();
    let _ = s.event_tx.send(json!({"event": "connected", "data": {}}));
    let stream = futures_util::StreamExt::filter_map(
        tokio_stream::wrappers::BroadcastStream::new(rx),
        |item| async move {
            match item {
                Ok(ev) => {
                    let data = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_string());
                    let e = ev
                        .get("event")
                        .and_then(|v| v.as_str())
                        .unwrap_or("event")
                        .to_string();
                    Some(Ok::<_, std::convert::Infallible>(
                        axum::response::sse::Event::default().event(&e).data(data),
                    ))
                }
                // Lagged / channel closed：跳过。
                Err(_) => None,
            }
        },
    );
    axum::response::Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new().interval(std::time::Duration::from_secs(15)),
    )
}

async fn get_blocked(State(s): State<Arc<AppState>>) -> Json<BlockedOut> {
    let guard = s.blocked.lock().unwrap();
    let mut entries = Vec::with_capacity(guard.len());
    for (k, e) in guard.iter() {
        entries.push(BlockedEntryOut {
            ip: k.to_string(),
            reason: e.reason.clone(),
            added_unix: e.added_unix,
            expire_unix: e.expire_unix,
        });
    }
    Json(BlockedOut { entries })
}

async fn block(
    State(s): State<Arc<AppState>>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<Status>, ApiError> {
    let ip = req
        .ip
        .parse::<IpAddr>()
        .map_err(|_| ApiError::bad_request(format!("invalid IP: {}", req.ip)))?;
    s.block(ip, req.seconds, req.reason.unwrap_or_default())
        .await?;
    info!("block {} via API", ip);
    Ok(Json(status_inner(&s)))
}

async fn unblock(
    State(s): State<Arc<AppState>>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<Status>, ApiError> {
    let ip = req
        .ip
        .parse::<IpAddr>()
        .map_err(|_| ApiError::bad_request(format!("invalid IP: {}", req.ip)))?;
    s.unblock(ip).await?;
    info!("unblock {} via API", ip);
    Ok(Json(status_inner(&s)))
}

async fn openapi_json() -> Json<Value> {
    Json(crate::openapi::openapi_doc())
}

async fn docs() -> axum::response::Html<String> {
    let html = scalar_api_reference::scalar_html_default(&json!({
        "url": "/openapi.json",
        "theme": "purple",
        "darkMode": true,
    }));
    axum::response::Html(html)
}

/// HTTP API 认证：校验请求携带的 API Key。
///
/// 认证头支持两种形式（二选一）：
/// - `Authorization: Bearer <key>`
/// - `X-API-Key: <key>`
///
/// 认证语义由 `strict` 决定：
/// - `strict = false`（Unix socket，本机 CLI）：未配置 `daemon.api_keys` 时放行（保持兼容）。
/// - `strict = true`（TCP/HTTP，默认 0.0.0.0）：`api_keys` 为空时**拒绝所有请求**
///   （fail-closed），避免未配置密钥即把管理接口暴露到网络。
pub async fn require_api_key(
    State(state): State<Arc<AppState>>,
    strict: bool,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if state.api_keys.is_empty() {
        if strict {
            return Err(ApiError::unauthorized());
        }
        return Ok(next.run(req).await);
    }
    let provided = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::to_owned)
        .or_else(|| {
            req.headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        });
    match provided {
        Some(key) if state.api_keys.iter().any(|k| ct_eq(k.as_bytes(), key.as_bytes())) => {
            Ok(next.run(req).await)
        }
        _ => Err(ApiError::unauthorized()),
    }
}

/// 恒定时间字符串比较，避免通过响应时间差逐字节猜测 API Key。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// GET /api/v1/auth/verify：返回当前认证状态（配合中间件使用，未通过不会到达这里）。
async fn auth_verify(State(s): State<Arc<AppState>>) -> Json<Value> {
    Json(json!({
        "valid": true,
        "auth_enabled": !s.api_keys.is_empty(),
    }))
}

/// `/api/v1` 统一响应信封：把 handler 的原始 JSON / text 响应包成
/// `{code, message, data}`，HTTP 状态码保持不变。
///
/// - 2xx：`data` = 原响应体，`message` = "ok"。
/// - 非 2xx（ApiError 的 `{error: msg}`）：`data` = null，`message` = 原错误。
/// - text/plain（规则/配置导出）：`data` = 原文本。
pub async fn wrap_envelope(req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    let status = resp.status();
    let is_text = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("text/plain"))
        .unwrap_or(false);
    let is_sse = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("text/event-stream"))
        .unwrap_or(false);
    if is_sse {
        // SSE 是持续流，不能缓冲进信封；直接透传。
        return resp;
    }
    let bytes = match axum::body::to_bytes(resp.into_body(), 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => {
            return envelope(
                status,
                json!({"code": 500, "message": "failed to read response body", "data": null}),
            );
        }
    };
    if is_text {
        let text = String::from_utf8_lossy(&bytes).to_string();
        return envelope(
            status,
            json!({"code": status.as_u16(), "message": "ok", "data": text}),
        );
    }
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(_) => {
            return envelope(
                status,
                json!({"code": status.as_u16(), "message": "non-JSON response", "data": null}),
            );
        }
    };
    if status.is_success() {
        envelope(
            status,
            json!({"code": status.as_u16(), "message": "ok", "data": value}),
        )
    } else {
        let msg = value
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("error")
            .to_string();
        envelope(
            status,
            json!({"code": status.as_u16(), "message": msg, "data": null}),
        )
    }
}

fn envelope(status: StatusCode, body: Value) -> Response {
    (status, Json(body)).into_response()
}

// ============================================================================
// /api/v1/operational/*：运维查询
// ============================================================================

/// 判断 `ip` 文本是否命中 `cidr`（`192.168.10.0/24`，无前缀按 /32、/128 处理）。
fn cidr_match_ip(ip: &str, cidr: &str) -> Result<bool> {
    let (net_str, prefix) = match cidr.split_once('/') {
        Some((n, p)) => {
            let p: u8 = p
                .parse()
                .map_err(|_| anyhow!("bad CIDR prefix in {cidr:?}"))?;
            (n, Some(p))
        }
        None => (cidr, None),
    };
    let net: IpAddr = net_str.parse().map_err(|_| anyhow!("bad CIDR {cidr:?}"))?;
    let ip: IpAddr = ip.parse().map_err(|_| anyhow!("bad IP {ip:?}"))?;
    let (net_bits, ip_bits, is_v4) = match (net, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => (u32::from(a) as u128, u32::from(b) as u128, true),
        (IpAddr::V6(a), IpAddr::V6(b)) => (u128::from(a), u128::from(b), false),
        _ => return Ok(false),
    };
    let max = if is_v4 { 32 } else { 128 };
    let prefix = prefix.map(|p| p.min(max)).unwrap_or(max);
    let mask: u128 = if is_v4 {
        if prefix == 0 {
            0
        } else {
            0xFFFF_FFFFu128 << (32 - prefix)
        }
    } else if prefix == 0 {
        0
    } else {
        0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128 << (128 - prefix)
    };
    Ok(net_bits & mask == ip_bits & mask)
}

async fn get_sessions(
    State(s): State<Arc<AppState>>,
    Query(q): Query<SessionListQuery>,
) -> Result<Json<SessionsOut>, ApiError> {
    let entries: Vec<SessionOut> = {
        let mut handle = s.handle.lock().await;
        handle
            .dump_sessions()
            .map_err(|e| ApiError::bad_request(e.to_string()))?
    };
    let mut entries: Vec<SessionOut> = entries
        .into_iter()
        .filter(|e| {
            if let Some(f) = &q.family {
                if !e.family.eq_ignore_ascii_case(f) {
                    return false;
                }
            }
            if let Some(p) = &q.proto {
                if !e.proto.eq_ignore_ascii_case(p) {
                    return false;
                }
            }
            if let Some(v) = &q.src_ip {
                if &e.src_ip != v {
                    return false;
                }
            }
            if let Some(v) = &q.dst_ip {
                if &e.dst_ip != v {
                    return false;
                }
            }
            if let Some(v) = q.src_port {
                if e.src_port != v {
                    return false;
                }
            }
            if let Some(v) = q.dst_port {
                if e.dst_port != v {
                    return false;
                }
            }
            if let Some(c) = &q.src_cidr {
                match cidr_match_ip(&e.src_ip, c) {
                    Ok(true) => {}
                    _ => return false,
                }
            }
            if let Some(c) = &q.dst_cidr {
                match cidr_match_ip(&e.dst_ip, c) {
                    Ok(true) => {}
                    _ => return false,
                }
            }
            if let Some(a) = &q.app_proto {
                if !e
                    .app_proto
                    .as_deref()
                    .is_some_and(|v| v.eq_ignore_ascii_case(a))
                {
                    return false;
                }
            }
            if let Some(s) = &q.tls_sni {
                if !e
                    .tls_sni
                    .as_deref()
                    .is_some_and(|v| v.to_ascii_lowercase().contains(&s.to_ascii_lowercase()))
                {
                    return false;
                }
            }
            if let Some(h) = &q.http_host {
                if !e
                    .http_host
                    .as_deref()
                    .is_some_and(|v| v.to_ascii_lowercase().contains(&h.to_ascii_lowercase()))
                {
                    return false;
                }
            }
            if let Some(d) = &q.dns_query {
                if !e
                    .dns_query
                    .as_deref()
                    .is_some_and(|v| v.to_ascii_lowercase().contains(&d.to_ascii_lowercase()))
                {
                    return false;
                }
            }
            if let Some(s) = &q.state {
                if !e.state.eq_ignore_ascii_case(s) {
                    return false;
                }
            }
            if let Some(kw) = &q.q {
                let kw = kw.to_ascii_lowercase();
                let haystack = [
                    e.app_proto.as_deref(),
                    e.tls_sni.as_deref(),
                    e.http_host.as_deref(),
                    e.http_user_agent.as_deref(),
                    e.dns_query.as_deref(),
                    e.app_info.as_deref(),
                    Some(e.src_ip.as_str()),
                    Some(e.dst_ip.as_str()),
                ]
                .into_iter()
                .flatten()
                .any(|v| v.to_ascii_lowercase().contains(&kw));
                if !haystack {
                    return false;
                }
            }
            true
        })
        .collect();
    match q.sort.as_deref().unwrap_or("last_seen") {
        "state" => entries.sort_by(|a, b| a.state.cmp(&b.state)),
        "packets" => entries.sort_by(|a, b| a.packets.cmp(&b.packets)),
        "bytes" => entries.sort_by(|a, b| {
            let at = a.bytes_orig + a.bytes_repl;
            let bt = b.bytes_orig + b.bytes_repl;
            at.cmp(&bt)
        }),
        _ => entries.sort_by(|a, b| a.last_seen_ns.cmp(&b.last_seen_ns)),
    }
    let total = entries.len();
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(100).min(1000);
    let start = (page - 1) * limit;
    let entries = entries.into_iter().skip(start).take(limit).collect();
    Ok(Json(SessionsOut { total, entries }))
}

/// DELETE /api/v1/operational/sessions：按过滤器删除会话（空过滤器 = 清空全部）。
async fn delete_sessions(
    State(s): State<Arc<AppState>>,
    filter: Option<Json<SessionDeleteRequest>>,
) -> Result<Json<SessionsDeleteOut>, ApiError> {
    let filter = filter.map(|j| j.0).unwrap_or_default();
    let removed = s
        .handle
        .lock()
        .await
        .delete_sessions(&filter)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(SessionsDeleteOut {
        removed: removed as usize,
    }))
}

/// DELETE /api/v1/operational/sessions/{session_id}：按会话 ID 精确切断单个会话。
async fn delete_session(
    State(s): State<Arc<AppState>>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<SessionsDeleteOut>, ApiError> {
    let removed = s
        .handle
        .lock()
        .await
        .delete_session_by_id(&session_id)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if removed == 0 {
        return Err(ApiError::not_found("session not found"));
    }
    Ok(Json(SessionsDeleteOut { removed }))
}

fn blocklist_inner(s: &AppState) -> BlocklistOut {
    let guard = s.blocked.lock().unwrap();
    let entries: Vec<BlocklistEntryOut> = guard
        .iter()
        .map(|(ip, e)| BlocklistEntryOut {
            ip: ip.to_string(),
            reason: e.reason.clone(),
            added_unix: e.added_unix,
            expire_unix: e.expire_unix,
        })
        .collect();
    BlocklistOut { entries }
}

async fn get_blocklist(State(s): State<Arc<AppState>>) -> Json<BlocklistOut> {
    Json(blocklist_inner(&s))
}

/// POST /api/v1/operational/blocklist：封禁一个 IP（可选过期秒数 + 原因）。
async fn add_blocklist_entry(
    State(s): State<Arc<AppState>>,
    Json(req): Json<BlockRequest>,
) -> Result<Json<BlocklistOut>, ApiError> {
    let ip = req
        .ip
        .parse::<IpAddr>()
        .map_err(|_| ApiError::bad_request(format!("invalid IP: {}", req.ip)))?;
    s.block(ip, req.seconds, req.reason.unwrap_or_default())
        .await?;
    info!("block {} via API", ip);
    Ok(Json(blocklist_inner(&s)))
}

/// DELETE /api/v1/operational/blocklist/{ip}：解除封禁。
async fn delete_blocklist_entry(
    State(s): State<Arc<AppState>>,
    AxumPath(ip): AxumPath<String>,
) -> Result<Json<BlocklistOut>, ApiError> {
    let ip = ip
        .parse::<IpAddr>()
        .map_err(|_| ApiError::bad_request(format!("invalid IP: {ip}")))?;
    s.unblock(ip).await?;
    info!("unblock {} via API", ip);
    Ok(Json(blocklist_inner(&s)))
}

/// GET /api/v1/operational/stats/interfaces：每网卡 sysfs 收发统计。
async fn get_interface_stats(
    State(s): State<Arc<AppState>>,
) -> Result<Json<InterfaceStatsOut>, ApiError> {
    let mut entries = Vec::new();
    for name in &s.attach_ifaces {
        let read = |field: &str| -> u64 {
            std::fs::read_to_string(format!("/sys/class/net/{name}/statistics/{field}"))
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0)
        };
        entries.push(InterfaceStats {
            name: name.clone(),
            rx_packets: read("rx_packets"),
            rx_bytes: read("rx_bytes"),
            rx_dropped: read("rx_dropped"),
            tx_packets: read("tx_packets"),
            tx_bytes: read("tx_bytes"),
            tx_dropped: read("tx_dropped"),
        });
    }
    Ok(Json(InterfaceStatsOut { entries }))
}

// ============================================================================
// /api/v1/system/info
// ============================================================================

async fn system_info(State(s): State<Arc<AppState>>) -> Json<Value> {
    let kernel = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    Json(json!({
        "name": "k-firewall",
        "version": env!("CARGO_PKG_VERSION"),
        "iface": s.iface,
        "uptime_secs": SystemTime::now().duration_since(s.started).unwrap_or_default().as_secs(),
        "rule_count": s.suricata_rules.lock().unwrap().len(),
        "blocked_count": s.blocked.lock().unwrap().len(),
        "auth_enabled": !s.api_keys.is_empty(),
        "kernel": kernel,
    }))
}

/// GET /api/v1/system/interfaces：逻辑接口信息（只读）。
async fn get_interfaces(State(s): State<Arc<AppState>>) -> Json<InterfacesOut> {
    let mut entries = Vec::new();
    for c in &s.interfaces {
        let ifindex: u32 = std::fs::read_to_string(format!("/sys/class/net/{}/ifindex", c.name))
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let mac = std::fs::read_to_string(format!("/sys/class/net/{}/address", c.name))
            .ok()
            .map(|v| v.trim().to_string());
        let carrier = std::fs::read_to_string(format!("/sys/class/net/{}/carrier", c.name))
            .ok()
            .map(|v| v.trim() == "1")
            .unwrap_or(false);
        entries.push(InterfaceInfo {
            name: c.name.clone(),
            role: c.role.clone(),
            mode: c.mode.clone(),
            nat: c.nat.clone(),
            address: c.address.map(|a| a.to_string()),
            netmask: c.netmask.map(|a| a.to_string()),
            ifindex,
            mac,
            carrier,
        });
    }
    Json(InterfacesOut { entries })
}

/// GET /api/v1/system/config：备份当前配置文件（text/plain）。
async fn get_system_config(State(s): State<Arc<AppState>>) -> Response {
    let Some(path) = &s.config_path else {
        return ApiError::not_found("config path not tracked (daemon started without --config?)")
            .into_response();
    };
    match std::fs::read_to_string(path) {
        Ok(text) => Response::builder()
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(text))
            .expect("static response"),
        Err(e) => {
            ApiError::not_found(format!("failed to read {}: {e}", path.display())).into_response()
        }
    }
}

/// POST /api/v1/system/config：恢复配置文件（YAML 文本，校验通过后写入）。
async fn post_system_config(
    State(s): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<ConfigRestoreOut>, ApiError> {
    let Some(path) = &s.config_path else {
        return Err(ApiError::not_found(
            "config path not tracked (daemon started without --config?)",
        ));
    };
    let body = String::from_utf8_lossy(&body).to_string();
    let cfg = Config::from_str(&body).map_err(|e| ApiError::bad_request(e.to_string()))?;
    let _ = cfg;
    // 原子写：先写同目录临时文件再 rename，避免写入中途崩溃留下截断/半写的配置。
    let tmp = path.with_extension("yaml.tmp");
    std::fs::write(&tmp, &body)
        .map_err(|e| ApiError::internal(format!("failed to write {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| ApiError::internal(format!("failed to replace {}: {e}", path.display())))?;
    info!("config restored via API to {}", path.display());
    Ok(Json(ConfigRestoreOut {
        accepted: true,
        message: "config written; restart required for full effect".into(),
    }))
}

/// POST /api/v1/system/config/validate：只校验，不落盘。
async fn post_system_config_validate(
    State(_s): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Json<ConfigValidateOut> {
    let text = String::from_utf8_lossy(&body).to_string();
    match Config::from_str(&text) {
        Ok(_) => Json(ConfigValidateOut {
            valid: true,
            errors: Vec::new(),
        }),
        Err(e) => Json(ConfigValidateOut {
            valid: false,
            errors: vec![e.to_string()],
        }),
    }
}

/// POST /api/v1/system/config/diff：与当前落盘配置做 YAML 顶层键差异。
async fn post_system_config_diff(
    State(s): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Json<ConfigDiffOut> {
    let text = String::from_utf8_lossy(&body).to_string();
    if let Err(e) = Config::from_str(&text) {
        return Json(ConfigDiffOut {
            valid: false,
            changed_keys: Vec::new(),
            summary: vec![format!("invalid config: {e}")],
        });
    }
    let mut changed_keys = Vec::new();
    let mut summary = Vec::new();
    if let Some(path) = &s.config_path {
        if let Ok(cur) = std::fs::read_to_string(path) {
            let cur: serde_yaml_ng::Value = serde_yaml_ng::from_str(&cur).unwrap_or_default();
            let new: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text).unwrap_or_default();
            if let (Some(cmap), Some(nmap)) = (cur.as_mapping(), new.as_mapping()) {
                let mut keys: Vec<&str> = Vec::new();
                for k in nmap.keys() {
                    if let Some(k) = k.as_str() {
                        keys.push(k);
                    }
                }
                for k in cmap.keys() {
                    if let Some(k) = k.as_str() {
                        if !keys.contains(&k) {
                            keys.push(k);
                        }
                    }
                }
                keys.sort_unstable();
                for k in keys {
                    let cv = cmap.get(k).cloned().unwrap_or(serde_yaml_ng::Value::Null);
                    let nv = nmap.get(k).cloned().unwrap_or(serde_yaml_ng::Value::Null);
                    if cv != nv {
                        changed_keys.push(k.to_string());
                        summary.push(format!("{k}: changed"));
                    }
                }
            }
        } else {
            summary.push("current config unreadable; diff skipped".into());
        }
    } else {
        summary.push("no tracked config file; diff skipped".into());
    }
    Json(ConfigDiffOut {
        valid: true,
        changed_keys,
        summary,
    })
}

/// POST /api/v1/system/reload：重新读取并校验磁盘上的配置。
///
/// 说明：完整热生效（eBPF 程序重挂载）需要重启；当前只做 校验 + 重新加载 Suricata 预过滤开关。
async fn post_system_reload(
    State(s): State<Arc<AppState>>,
) -> Result<Json<ConfigRestoreOut>, ApiError> {
    let Some(path) = &s.config_path else {
        return Err(ApiError::not_found(
            "config path not tracked (daemon started without --config?)",
        ));
    };
    let text = std::fs::read_to_string(path)
        .map_err(|e| ApiError::internal(format!("failed to read {}: {e}", path.display())))?;
    let cfg = Config::from_str(&text)
        .map_err(|e| ApiError::bad_request(format!("invalid config: {e}")))?;
    // 热生效部分：Suricata 规则预过滤开关。
    {
        let old = s
            .suricata_prefilter
            .swap(cfg.suricata.prefilter, std::sync::atomic::Ordering::Relaxed);
        if old != cfg.suricata.prefilter {
            s.resync_suri_prefilter().await?;
        }
    }
    info!("config reloaded from {}", path.display());
    Ok(Json(ConfigRestoreOut {
        accepted: true,
        message: "config reloaded; XDP/接口变更需重启完全生效".into(),
    }))
}

// ============================================================================
// /api/v1/suricata/rules：Suricata 规则 CRUD（WebAPI 只收规则文本）
// ============================================================================

/// GET /api/v1/suricata/rules 查询参数（分页 + 文本过滤）。
#[derive(Deserialize)]
struct SuriListQuery {
    page: Option<usize>,
    limit: Option<usize>,
    #[serde(default)]
    q: Option<String>,
}

async fn list_suri_rules(
    State(s): State<Arc<AppState>>,
    Query(q): Query<SuriListQuery>,
) -> Json<SuricataRuleListOut> {
    let all = s.suri_rules_out();
    let filtered: Vec<SuricataRuleOut> = match &q.q {
        Some(kw) if !kw.is_empty() => {
            let kw = kw.to_ascii_lowercase();
            all.into_iter()
                .filter(|r| r.suricata_str.to_ascii_lowercase().contains(&kw))
                .collect()
        }
        _ => all,
    };
    let total = filtered.len();
    let page = q.page.unwrap_or(1).max(1);
    let limit = q.limit.unwrap_or(100).min(1000);
    let start = (page - 1) * limit;
    let entries = filtered.into_iter().skip(start).take(limit).collect();
    Json(SuricataRuleListOut { total, entries })
}

/// GET /api/v1/suricata/prefilter/stats：规则头预过滤状态与表容量。
async fn get_suri_prefilter_stats(
    State(s): State<Arc<AppState>>,
) -> Result<Json<SuricataPrefilterStats>, ApiError> {
    let st = s
        .handle
        .lock()
        .await
        .read_prefilter_stats()
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(st))
}

async fn add_suri_rule(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SuricataRuleRequest>,
) -> Result<Json<SuricataRuleOut>, ApiError> {
    if req.rule.trim().is_empty() {
        return Err(ApiError::bad_request("rule is required"));
    }
    let out = s
        .add_suri_rule(&req.rule)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(out))
}

async fn import_suri_rules(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SuricataRuleImportRequest>,
) -> Result<Json<SuricataRuleImportOut>, ApiError> {
    let out = s
        .import_suri_rules(req.rules)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(out))
}

async fn delete_suri_rule(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Result<Json<Vec<SuricataRuleOut>>, ApiError> {
    let removed = s
        .delete_suri_rule(id)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !removed {
        return Err(ApiError::bad_request(format!(
            "suricata rule {id} not found"
        )));
    }
    Ok(Json(s.suri_rules_out()))
}

/// PATCH /api/v1/suricata/rules/{id}：启停。
async fn patch_suri_rule(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<SuricataRulePatchRequest>,
) -> Result<Json<SuricataRuleOut>, ApiError> {
    if req.enabled.is_none() {
        return Err(ApiError::bad_request("enabled is required"));
    }
    let out = s
        .patch_suri_rule(id, req.enabled)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("suricata rule {id} not found")))
        .map(Json)
}

/// PUT /api/v1/suricata/rules/{id}：原地替换规则文本。
async fn update_suri_rule(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<SuricataRuleUpdateRequest>,
) -> Result<Json<SuricataRuleOut>, ApiError> {
    if req.rule.trim().is_empty() {
        return Err(ApiError::bad_request("rule is required"));
    }
    let out = s
        .update_suri_rule(id, &req.rule)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("suricata rule {id} not found")))
        .map(Json)
}

/// DELETE /api/v1/suricata/rules：按 ids 批量删除。
async fn delete_suri_rules(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SuricataRuleDeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.ids.is_empty() {
        return Err(ApiError::bad_request("ids is required"));
    }
    let removed = s
        .delete_suri_rules(&req.ids)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "removed": removed,
        "rules": s.suri_rules_out(),
    })))
}

async fn export_suri_rules(State(s): State<Arc<AppState>>) -> axum::response::Response {
    axum::response::Response::builder()
        .header("content-type", "text/plain; charset=utf-8")
        .body(axum::body::Body::from(s.export_suri_rules()))
        .expect("static response")
}

// /api/v1/qos/classes：QoS 分类 CRUD（热同步 QOS_CLASSES）
// ============================================================================

/// GET /api/v1/qos/classes：列出全部 QoS 分类。
async fn list_qos_classes(State(s): State<Arc<AppState>>) -> Json<QosClassListOut> {
    let entries = s.qos_classes_out();
    let total = entries.len();
    Json(QosClassListOut { total, entries })
}

/// POST /api/v1/qos/classes：新增一个 QoS 分类。
async fn add_qos_class(
    State(s): State<Arc<AppState>>,
    Json(req): Json<QosClassRequest>,
) -> Result<Json<QosClassOut>, ApiError> {
    let out = s
        .add_qos_class(&req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(out))
}

/// PUT /api/v1/qos/classes/{id}：原地替换。
async fn update_qos_class(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<QosClassUpdateRequest>,
) -> Result<Json<QosClassOut>, ApiError> {
    let out = s
        .update_qos_class(id, &req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("qos class {id} not found")))
        .map(Json)
}

/// PATCH /api/v1/qos/classes/{id}：启停。
async fn patch_qos_class(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<QosClassPatchRequest>,
) -> Result<Json<QosClassOut>, ApiError> {
    if req.enabled.is_none() {
        return Err(ApiError::bad_request("enabled is required"));
    }
    let out = s
        .patch_qos_class(id, req.enabled)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("qos class {id} not found")))
        .map(Json)
}

/// DELETE /api/v1/qos/classes/{id}：删除单个。
async fn delete_qos_class(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let removed = s
        .delete_qos_class(id)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !removed {
        return Err(ApiError::bad_request(format!("qos class {id} not found")));
    }
    Ok(Json(serde_json::json!({
        "removed": removed,
        "classes": s.qos_classes_out(),
    })))
}

/// DELETE /api/v1/qos/classes：按 ids 批量删除。
async fn delete_qos_classes(
    State(s): State<Arc<AppState>>,
    Json(req): Json<QosClassDeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.ids.is_empty() {
        return Err(ApiError::bad_request("ids is required"));
    }
    let removed = s
        .delete_qos_classes(&req.ids)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "removed": removed,
        "classes": s.qos_classes_out(),
    })))
}

// /api/v1/security/rate-limits：源 IP 速率限制 CRUD（热同步 RATE_LIMITS）
// ============================================================================

/// GET /api/v1/security/rate-limits：列出全部速率限制规则。
async fn list_rate_limits(State(s): State<Arc<AppState>>) -> Json<RateLimitListOut> {
    let entries = s.rate_limits_out();
    let total = entries.len();
    Json(RateLimitListOut { total, entries })
}

/// POST /api/v1/security/rate-limits：新增（id 可自定）。
async fn add_rate_limit(
    State(s): State<Arc<AppState>>,
    Json(req): Json<RateLimitRequest>,
) -> Result<Json<RateLimitOut>, ApiError> {
    let out = s
        .add_rate_limit(&req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(out))
}

/// PUT /api/v1/security/rate-limits/{id}：原地替换。
async fn update_rate_limit(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<RateLimitUpdateRequest>,
) -> Result<Json<RateLimitOut>, ApiError> {
    let out = s
        .update_rate_limit(id, &req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("rate limit {id} not found")))
        .map(Json)
}

/// PATCH /api/v1/security/rate-limits/{id}：启停。
async fn patch_rate_limit(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<QosClassPatchRequest>,
) -> Result<Json<RateLimitOut>, ApiError> {
    if req.enabled.is_none() {
        return Err(ApiError::bad_request("enabled is required"));
    }
    let out = s
        .patch_rate_limit(id, req.enabled)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("rate limit {id} not found")))
        .map(Json)
}

/// DELETE /api/v1/security/rate-limits/{id}：删除单个。
async fn delete_rate_limit(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let removed = s
        .delete_rate_limit(id)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !removed {
        return Err(ApiError::bad_request(format!("rate limit {id} not found")));
    }
    Ok(Json(serde_json::json!({
        "removed": removed,
        "entries": s.rate_limits_out(),
    })))
}

/// DELETE /api/v1/security/rate-limits：按 ids 批量删除。
async fn delete_rate_limits(
    State(s): State<Arc<AppState>>,
    Json(req): Json<RateLimitDeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.ids.is_empty() {
        return Err(ApiError::bad_request("ids is required"));
    }
    let removed = s
        .delete_rate_limits(&req.ids)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "removed": removed,
        "entries": s.rate_limits_out(),
    })))
}

/// POST /api/v1/security/rate-limits/swap：交换两条规则的执行顺序。
async fn swap_rate_limits(
    State(s): State<Arc<AppState>>,
    Json(req): Json<OrderSwapRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let out = s
        .swap_rate_limits(req.id_a, req.id_b)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    match out {
        Some((a, b)) => Ok(Json(serde_json::json!({
            "swapped": true,
            "a": a,
            "b": b,
            "entries": s.rate_limits_out(),
        }))),
        None => Err(ApiError::bad_request(
            "one or both ids not found (or id_a == id_b)",
        )),
    }
}

// /api/v1/security/conn-limits：每源并发连接数限制 CRUD（热同步 CONN_LIMITS）
// ============================================================================

/// GET /api/v1/security/conn-limits：列出全部并发连接数限制规则。
async fn list_conn_limits(State(s): State<Arc<AppState>>) -> Json<ConnLimitListOut> {
    let entries = s.conn_limits_out();
    let total = entries.len();
    Json(ConnLimitListOut { total, entries })
}

/// POST /api/v1/security/conn-limits：新增（id 可自定）。
async fn add_conn_limit(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ConnLimitRequest>,
) -> Result<Json<ConnLimitOut>, ApiError> {
    let out = s
        .add_conn_limit(&req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(out))
}

/// PUT /api/v1/security/conn-limits/{id}：原地替换。
async fn update_conn_limit(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<ConnLimitUpdateRequest>,
) -> Result<Json<ConnLimitOut>, ApiError> {
    let out = s
        .update_conn_limit(id, &req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("conn limit {id} not found")))
        .map(Json)
}

/// PATCH /api/v1/security/conn-limits/{id}：启停。
async fn patch_conn_limit(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<QosClassPatchRequest>,
) -> Result<Json<ConnLimitOut>, ApiError> {
    if req.enabled.is_none() {
        return Err(ApiError::bad_request("enabled is required"));
    }
    let out = s
        .patch_conn_limit(id, req.enabled)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("conn limit {id} not found")))
        .map(Json)
}

/// DELETE /api/v1/security/conn-limits/{id}：删除单个。
async fn delete_conn_limit(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let removed = s
        .delete_conn_limit(id)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !removed {
        return Err(ApiError::bad_request(format!("conn limit {id} not found")));
    }
    Ok(Json(serde_json::json!({
        "removed": removed,
        "entries": s.conn_limits_out(),
    })))
}

/// DELETE /api/v1/security/conn-limits：按 ids 批量删除。
async fn delete_conn_limits(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ConnLimitDeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.ids.is_empty() {
        return Err(ApiError::bad_request("ids is required"));
    }
    let removed = s
        .delete_conn_limits(&req.ids)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "removed": removed,
        "entries": s.conn_limits_out(),
    })))
}

/// POST /api/v1/security/conn-limits/swap：交换两条规则的执行顺序。
async fn swap_conn_limits(
    State(s): State<Arc<AppState>>,
    Json(req): Json<OrderSwapRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let out = s
        .swap_conn_limits(req.id_a, req.id_b)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    match out {
        Some((a, b)) => Ok(Json(serde_json::json!({
            "swapped": true,
            "a": a,
            "b": b,
            "entries": s.conn_limits_out(),
        }))),
        None => Err(ApiError::bad_request(
            "one or both ids not found (or id_a == id_b)",
        )),
    }
}

// /api/v1/security/syn-flood：SYN Flood 全局防护配置
// ============================================================================

/// GET /api/v1/security/syn-flood：读取配置。
async fn get_syn_flood(State(s): State<Arc<AppState>>) -> Json<SynFloodOut> {
    Json(s.syn_flood_out())
}

/// PUT /api/v1/security/syn-flood：整体替换配置。
async fn put_syn_flood(
    State(s): State<Arc<AppState>>,
    Json(req): Json<SynFloodRequest>,
) -> Result<Json<SynFloodOut>, ApiError> {
    let out = s
        .update_syn_flood(&req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(out))
}

// /api/v1/nat/rules：DNAT 端口转发规则 CRUD（热同步 DNAT_RULES）
// ============================================================================

/// GET /api/v1/nat/rules：列出全部 NAT 规则。
async fn list_nat_rules(State(s): State<Arc<AppState>>) -> Json<NatRuleListOut> {
    let entries = s.nat_rules_out();
    let total = entries.len();
    Json(NatRuleListOut { total, entries })
}

/// POST /api/v1/nat/rules：新增（id 可自定）。
async fn add_nat_rule(
    State(s): State<Arc<AppState>>,
    Json(req): Json<NatRuleRequest>,
) -> Result<Json<NatRuleOut>, ApiError> {
    let out = s
        .add_nat_rule(&req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(out))
}

/// PUT /api/v1/nat/rules/{id}：原地替换。
async fn update_nat_rule(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<NatRuleUpdateRequest>,
) -> Result<Json<NatRuleOut>, ApiError> {
    let out = s
        .update_nat_rule(id, &req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("nat rule {id} not found")))
        .map(Json)
}

/// PATCH /api/v1/nat/rules/{id}：启停。
async fn patch_nat_rule(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<QosClassPatchRequest>,
) -> Result<Json<NatRuleOut>, ApiError> {
    if req.enabled.is_none() {
        return Err(ApiError::bad_request("enabled is required"));
    }
    let out = s
        .patch_nat_rule(id, req.enabled)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("nat rule {id} not found")))
        .map(Json)
}

/// DELETE /api/v1/nat/rules/{id}：删除单个。
async fn delete_nat_rule(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let removed = s
        .delete_nat_rule(id)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !removed {
        return Err(ApiError::bad_request(format!("nat rule {id} not found")));
    }
    Ok(Json(serde_json::json!({
        "removed": removed,
        "entries": s.nat_rules_out(),
    })))
}

/// DELETE /api/v1/nat/rules：按 ids 批量删除。
async fn delete_nat_rules(
    State(s): State<Arc<AppState>>,
    Json(req): Json<NatRuleDeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.ids.is_empty() {
        return Err(ApiError::bad_request("ids is required"));
    }
    let removed = s
        .delete_nat_rules(&req.ids)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "removed": removed,
        "entries": s.nat_rules_out(),
    })))
}

/// POST /api/v1/nat/rules/swap：交换两条规则的执行顺序。
async fn swap_nat_rules(
    State(s): State<Arc<AppState>>,
    Json(req): Json<OrderSwapRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let out = s
        .swap_nat_rules(req.id_a, req.id_b)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    match out {
        Some((a, b)) => Ok(Json(serde_json::json!({
            "swapped": true,
            "a": a,
            "b": b,
            "entries": s.nat_rules_out(),
        }))),
        None => Err(ApiError::bad_request(
            "one or both ids not found (or id_a == id_b)",
        )),
    }
}

// /api/v1/zones：Zone 策略 CRUD（热同步 ZONE；id 顺序即执行顺序）
// ============================================================================

/// GET /api/v1/zones：列出全部 Zone 策略。
async fn list_zone_policies(State(s): State<Arc<AppState>>) -> Json<ZonePolicyListOut> {
    let entries = s.zone_policies_out();
    let total = entries.len();
    Json(ZonePolicyListOut { total, entries })
}

/// POST /api/v1/zones：新增（id 可自定）。
async fn add_zone_policy(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ZonePolicyRequest>,
) -> Result<Json<ZonePolicyOut>, ApiError> {
    let out = s
        .add_zone_policy(&req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(out))
}

/// PUT /api/v1/zones/{id}：原地替换。
async fn update_zone_policy(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<ZonePolicyUpdateRequest>,
) -> Result<Json<ZonePolicyOut>, ApiError> {
    let out = s
        .update_zone_policy(id, &req)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("zone policy {id} not found")))
        .map(Json)
}

/// PATCH /api/v1/zones/{id}：启停。
async fn patch_zone_policy(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
    Json(req): Json<QosClassPatchRequest>,
) -> Result<Json<ZonePolicyOut>, ApiError> {
    if req.enabled.is_none() {
        return Err(ApiError::bad_request("enabled is required"));
    }
    let out = s
        .patch_zone_policy(id, req.enabled)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    out.ok_or_else(|| ApiError::bad_request(format!("zone policy {id} not found")))
        .map(Json)
}

/// DELETE /api/v1/zones/{id}：删除单个。
async fn delete_zone_policy(
    State(s): State<Arc<AppState>>,
    AxumPath(id): AxumPath<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let removed = s
        .delete_zone_policy(id)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    if !removed {
        return Err(ApiError::bad_request(format!("zone policy {id} not found")));
    }
    Ok(Json(serde_json::json!({
        "removed": removed,
        "entries": s.zone_policies_out(),
    })))
}

/// DELETE /api/v1/zones：按 ids 批量删除。
async fn delete_zone_policies(
    State(s): State<Arc<AppState>>,
    Json(req): Json<ZonePolicyDeleteRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if req.ids.is_empty() {
        return Err(ApiError::bad_request("ids is required"));
    }
    let removed = s
        .delete_zone_policies(&req.ids)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "removed": removed,
        "entries": s.zone_policies_out(),
    })))
}

/// POST /api/v1/zones/swap：交换两条策略的执行顺序。
async fn swap_zone_policies(
    State(s): State<Arc<AppState>>,
    Json(req): Json<OrderSwapRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let out = s
        .swap_zone_policies(req.id_a, req.id_b)
        .await
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    match out {
        Some((a, b)) => Ok(Json(serde_json::json!({
            "swapped": true,
            "a": a,
            "b": b,
            "entries": s.zone_policies_out(),
        }))),
        None => Err(ApiError::bad_request(
            "one or both ids not found (or id_a == id_b)",
        )),
    }
}

fn router(state: Arc<AppState>, strict_auth: bool) -> Router {
    // 所有端点（含扁平兼容路由）都必须携带 API Key。`strict_auth` 控制
    // `api_keys` 为空时的行为：HTTP 服务强制拒绝（fail-closed），Unix socket
    // 本机 CLI 保持放行。
    let require_key = middleware::from_fn_with_state(
        state.clone(),
        move |State(s): State<Arc<AppState>>, req: Request, next: Next| {
            require_api_key(State(s), strict_auth, req, next)
        },
    );
    // /api/v1：所有端点都必须携带 API Key（`Authorization: Bearer <key>` 或 `X-API-Key: <key>`）。
    let api_v1 = Router::new()
        .route("/auth/verify", get(auth_verify))
        .route(
            "/operational/sessions",
            get(get_sessions).delete(delete_sessions),
        )
        .route("/operational/sessions/{session_id}", delete(delete_session))
        .route(
            "/operational/blocklist",
            get(get_blocklist).post(add_blocklist_entry),
        )
        .route(
            "/operational/blocklist/{ip}",
            delete(delete_blocklist_entry),
        )
        .route("/operational/stats", get(get_stats))
        .route("/operational/stats/interfaces", get(get_interface_stats))
        .route("/operational/events", get(sse_events))
        .route("/system/info", get(system_info))
        .route("/system/interfaces", get(get_interfaces))
        .route(
            "/system/config",
            get(get_system_config).post(post_system_config),
        )
        .route("/system/config/validate", post(post_system_config_validate))
        .route("/system/config/diff", post(post_system_config_diff))
        .route("/system/reload", post(post_system_reload))
        .route("/suricata/rules", get(list_suri_rules).post(add_suri_rule))
        .route("/suricata/prefilter/stats", get(get_suri_prefilter_stats))
        .route("/suricata/rules/import", post(import_suri_rules))
        .route("/suricata/rules/export", get(export_suri_rules))
        .route(
            "/suricata/rules/{id}",
            delete(delete_suri_rule)
                .patch(patch_suri_rule)
                .put(update_suri_rule),
        )
        .route("/suricata/rules", delete(delete_suri_rules))
        .route("/qos/classes", get(list_qos_classes).post(add_qos_class))
        .route(
            "/qos/classes/{id}",
            put(update_qos_class)
                .patch(patch_qos_class)
                .delete(delete_qos_class),
        )
        .route("/qos/classes", delete(delete_qos_classes))
        .route(
            "/security/rate-limits",
            get(list_rate_limits).post(add_rate_limit),
        )
        .route("/security/rate-limits/swap", post(swap_rate_limits))
        .route(
            "/security/rate-limits/{id}",
            put(update_rate_limit)
                .patch(patch_rate_limit)
                .delete(delete_rate_limit),
        )
        .route("/security/rate-limits", delete(delete_rate_limits))
        .route(
            "/security/conn-limits",
            get(list_conn_limits).post(add_conn_limit),
        )
        .route("/security/conn-limits/swap", post(swap_conn_limits))
        .route(
            "/security/conn-limits/{id}",
            put(update_conn_limit)
                .patch(patch_conn_limit)
                .delete(delete_conn_limit),
        )
        .route("/security/conn-limits", delete(delete_conn_limits))
        .route(
            "/security/syn-flood",
            get(get_syn_flood).put(put_syn_flood),
        )
        .route("/nat/rules", get(list_nat_rules).post(add_nat_rule))
        .route("/nat/rules/swap", post(swap_nat_rules))
        .route(
            "/nat/rules/{id}",
            put(update_nat_rule)
                .patch(patch_nat_rule)
                .delete(delete_nat_rule),
        )
        .route("/nat/rules", delete(delete_nat_rules))
        .route("/zones", get(list_zone_policies).post(add_zone_policy))
        .route("/zones/swap", post(swap_zone_policies))
        .route(
            "/zones/{id}",
            put(update_zone_policy)
                .patch(patch_zone_policy)
                .delete(delete_zone_policy),
        )
        .route("/zones", delete(delete_zone_policies))
        .layer(require_key.clone())
        // 统一响应信封最外层：包裹成功/失败响应为 {code, message, data}。
        .layer(middleware::from_fn(wrap_envelope));

    // 兼容的扁平路由：同样要求认证；/openapi.json 与 /docs 为只读文档，
    // 不涉及状态修改，允许匿名访问。
    let flat = Router::new()
        .route("/status", get(status))
        .route("/stats", get(get_stats))
        .route("/blocked", get(get_blocked))
        .route("/block", post(block))
        .route("/unblock", post(unblock))
        .route("/metrics", get(metrics))
        .layer(require_key);

    let public = Router::new()
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs));

    Router::new()
        .nest("/api/v1", api_v1)
        .merge(flat)
        .merge(public)
        .with_state(state)
}

/// 在 Unix Domain Socket 上提供 REST API。
pub async fn serve(path: &Path, state: Arc<AppState>) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    // 让非 root 用户也能通过 CLI 连接（仅本机 Unix socket）
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));

    info!("API listening on {}", path.display());
    axum::serve(listener, router(state, false)).await?;
    Ok(())
}

/// 在 TCP/HTTP 端口上提供 REST API（`http_addr` 配置，如 0.0.0.0:8080）。
pub async fn serve_http(addr: &str, state: Arc<AppState>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {}", addr))?;
    info!("HTTP API listening on {}", addr);
    // HTTP 暴露到网络：api_keys 未配置时拒绝所有请求（fail-closed）。
    axum::serve(listener, router(state, true)).await?;
    Ok(())
}

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn bad_request(msg: impl Into<String>) -> Self {
        Self(StatusCode::BAD_REQUEST, msg.into())
    }

    fn not_found(msg: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, msg.into())
    }

    fn conflict(msg: impl Into<String>) -> Self {
        Self(StatusCode::CONFLICT, msg.into())
    }

    fn unprocessable(msg: impl Into<String>) -> Self {
        Self(StatusCode::UNPROCESSABLE_ENTITY, msg.into())
    }

    fn unauthorized() -> Self {
        Self(
            StatusCode::UNAUTHORIZED,
            "missing or invalid API key".into(),
        )
    }

    fn internal(msg: impl Into<String>) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut resp = (self.0, Json(Error { error: self.1 })).into_response();
        if resp.status() == StatusCode::UNAUTHORIZED {
            resp.headers_mut()
                .insert(WWW_AUTHENTICATE, "Bearer".parse().expect("static header"));
        }
        resp
    }
}

impl<E: std::fmt::Display> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}
