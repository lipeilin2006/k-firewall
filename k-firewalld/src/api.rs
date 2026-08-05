use std::collections::HashMap;
use std::net::IpAddr;
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
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use k_firewall_common::BlockEntry;
use k_firewall_common::api::{
    BlockRequest, BlockedEntryOut, BlockedOut, BlocklistEntryOut, BlocklistOut, ConfigDiffOut,
    ConfigRestoreOut, ConfigValidateOut, Error, InterfaceInfo, InterfaceStats, InterfaceStatsOut,
    InterfacesOut, SessionDeleteRequest, SessionListQuery, SessionOut, SessionsDeleteOut,
    SessionsOut, StatsOut, Status, SuricataPrefilterStats, SuricataRuleDeleteRequest,
    SuricataRuleImportOut, SuricataRuleImportRequest, SuricataRuleListOut, SuricataRuleOut,
    SuricataRulePatchRequest, SuricataRuleRequest, SuricataRuleUpdateRequest,
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

        Ok(Self {
            handle: tokio::sync::Mutex::new(handle),
            blocked: Mutex::new(blocked),
            iface: config.primary_iface(),
            suricata_rules: Mutex::new(Vec::new()),
            next_suri_rule_id: AtomicU64::new(1),
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
    let mut rx = s.event_tx.subscribe();
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
/// 未配置 `daemon.api_keys` 时跳过认证（保持向后兼容）；配置后所有 `/api/v1` 请求必须通过。
pub async fn require_api_key(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if state.api_keys.is_empty() {
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
        Some(key) if state.api_keys.iter().any(|k| k == &key) => Ok(next.run(req).await),
        _ => Err(ApiError::unauthorized()),
    }
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
    std::fs::write(path, &body)
        .map_err(|e| ApiError::internal(format!("failed to write {}: {e}", path.display())))?;
    info!("config restored via API to {}", path.display());
    Ok(Json(ConfigRestoreOut {
        accepted: true,
        message: "config written; restart required for full effect".into(),
    }))
}

/// POST /api/v1/system/config/validate：只校验，不落盘。
async fn post_system_config_validate(
    State(s): State<Arc<AppState>>,
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
            let cur: serde_yaml::Value = serde_yaml::from_str(&cur).unwrap_or_default();
            let new: serde_yaml::Value = serde_yaml::from_str(&text).unwrap_or_default();
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
                    let cv = cmap.get(k).cloned().unwrap_or(serde_yaml::Value::Null);
                    let nv = nmap.get(k).cloned().unwrap_or(serde_yaml::Value::Null);
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

fn router(state: Arc<AppState>) -> Router {
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
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        // 统一响应信封最外层：包裹成功/失败响应为 {code, message, data}。
        .layer(middleware::from_fn(wrap_envelope));

    Router::new()
        .nest("/api/v1", api_v1)
        // 兼容的扁平路由（无认证；建议新客户端使用 /api/v1）。
        .route("/status", get(status))
        .route("/stats", get(get_stats))
        .route("/blocked", get(get_blocked))
        .route("/block", post(block))
        .route("/unblock", post(unblock))
        .route("/metrics", get(metrics))
        .route("/openapi.json", get(openapi_json))
        .route("/docs", get(docs))
        .with_state(state)
}

/// 在 Unix Domain Socket 上提供 REST API。
pub async fn serve(path: &Path, state: Arc<AppState>) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    // 让非 root 用户也能通过 CLI 连接（仅本机 Unix socket）
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));

    info!("API listening on {}", path.display());
    axum::serve(listener, router(state)).await?;
    Ok(())
}

/// 在 TCP/HTTP 端口上提供 REST API（`http_addr` 配置，如 0.0.0.0:8080）。
pub async fn serve_http(addr: &str, state: Arc<AppState>) -> Result<()> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind {}", addr))?;
    info!("HTTP API listening on {}", addr);
    axum::serve(listener, router(state)).await?;
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
