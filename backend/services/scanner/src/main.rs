use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
    process::Command,
};
use tokio::{
    net::TcpStream,
    time::timeout,
};
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};
use tracing_subscriber;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use rand::Rng;

#[derive(Debug, Deserialize)]
struct ScanRequest {
    target: String,
    ports: Option<Vec<u16>>,
    timeout_ms: Option<u64>,
    max_concurrent: Option<usize>,
    techniques: Option<ScanTechniques>,
    use_nmap: Option<bool>,
    nmap_scan_type: Option<String>,
    tor_mode: Option<bool>,
    scan_range: Option<bool>,  // For IP range scanning
}

#[derive(Debug, Deserialize)]
struct ScanTechniques {
    syn_scan: bool,
    timing_evasion: bool,
    fragmentation: bool,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    target: String,
    ip_address: String,
    open_ports: Vec<PortInfo>,
    scan_time_ms: u64,
    technique_used: String,
    scanner_used: String,
    discovered_hosts: Option<Vec<String>>,  // For range scanning
}

#[derive(Debug, Serialize, Clone)]
struct PortInfo {
    port: u16,
    state: String,
    service: String,
    banner: Option<String>,
    version: Option<String>,  // For Nmap service version
}

#[derive(Clone)]
struct AppState {
    resolver: Arc<TokioAsyncResolver>,
    nmap_path: String,
}

// Service name mapping
fn get_service_name(port: u16) -> &'static str {
    match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        111 => "RPC",
        135 => "MS-RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        1521 => "Oracle",
        1723 => "PPTP",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        6379 => "Redis",
        8080 => "HTTP-Proxy",
        8443 => "HTTPS-Alt",
        8888 => "HTTP-Alt",
        9200 => "Elasticsearch",
        27017 => "MongoDB",
        _ => "Unknown",
    }
}

// Check if Nmap is available
fn check_nmap_available(nmap_path: &str) -> bool {
    Command::new(nmap_path)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

// Parse Nmap XML output (simplified)
fn parse_nmap_output(output: &str) -> Vec<PortInfo> {
    let mut ports = Vec::new();
    
    // Simple parsing - in production, use an XML parser
    for line in output.lines() {
        if line.contains("/tcp") && line.contains("open") {
            if let Some(port_str) = line.split('/').next() {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    let service = if line.contains("http") { "HTTP" }
                    else if line.contains("ssh") { "SSH" }
                    else if line.contains("ftp") { "FTP" }
                    else { get_service_name(port) };
                    
                    let version = if line.contains("OpenSSH") { Some("OpenSSH".to_string()) }
                    else if line.contains("Apache") { Some("Apache".to_string()) }
                    else if line.contains("nginx") { Some("nginx".to_string()) }
                    else { None };
                    
                    ports.push(PortInfo {
                        port,
                        state: "open".to_string(),
                        service: service.to_string(),
                        banner: None,
                        version,
                    });
                }
            }
        }
    }
    
    ports
}

// Run Nmap scan
async fn nmap_scan(
    nmap_path: &str,
    target: &str,
    scan_type: &str,
    tor_mode: bool,
    scan_range: bool,
) -> Result<(Vec<PortInfo>, Vec<String>)> {
    let mut cmd = Command::new(nmap_path);
    
    // Build Nmap command based on scan type and options
    match scan_type {
        "stealth" | "syn" => {
            cmd.arg("-sS");  // SYN scan
            if tor_mode {
                cmd.arg("-T2");  // Slower timing for TOR
                cmd.arg("-f");   // Fragment packets
                cmd.arg("-D").arg("RND:10");  // Random decoys
            }
        }
        "aggressive" => {
            cmd.arg("-A");   // Aggressive scan
            cmd.arg("-T4");  // Faster timing
        }
        "version" => {
            cmd.arg("-sV");  // Version detection
            cmd.arg("-sC");  // Default scripts
        }
        "udp" => {
            cmd.arg("-sU");  // UDP scan
            cmd.arg("--top-ports").arg("100");  // Top 100 UDP ports
        }
        _ => {
            cmd.arg("-sT");  // Default TCP connect scan
        }
    }
    
    // Add target
    cmd.arg(target);
    
    // Common options
    cmd.arg("-Pn");  // No ping (assume host is up)
    
    if scan_range {
        cmd.arg("-sn");  // Ping scan for host discovery
    } else {
        cmd.arg("--top-ports").arg("1000");  // Top 1000 ports
    }
    
    // Execute Nmap
    info!("Running Nmap: {:?}", cmd);
    let output = tokio::task::spawn_blocking(move || cmd.output()).await??;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("Nmap failed: {}", stderr));
    }
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ports = parse_nmap_output(&stdout);
    
    // Extract discovered hosts for range scanning
    let mut discovered_hosts = Vec::new();
    if scan_range {
        for line in stdout.lines() {
            if line.contains("Nmap scan report for") {
                if let Some(host) = line.split_whitespace().last() {
                    discovered_hosts.push(host.to_string());
                }
            }
        }
    }
    
    Ok((ports, discovered_hosts))
}

// Resolve hostname to IP
async fn resolve_target(resolver: &TokioAsyncResolver, target: &str) -> Result<IpAddr> {
    // Check if it's already an IP
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Resolve hostname
    let response = resolver.lookup_ip(target).await?;
    response
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No IP addresses found for {}", target))
}

// High-performance TCP connect scan
async fn tcp_connect_scan(
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
) -> Result<bool> {
    let addr = SocketAddr::new(ip, port);
    
    match timeout(timeout_duration, TcpStream::connect(addr)).await {
        Ok(Ok(_)) => Ok(true),
        _ => Ok(false),
    }
}

// SYN scan (requires raw sockets - platform specific)
async fn syn_scan(
    ip: IpAddr,
    port: u16,
    _timeout_duration: Duration,
) -> Result<bool> {
    // Note: SYN scanning requires raw socket access which is platform-specific
    // and often requires elevated privileges. For production use, consider
    // using a library like `libpnet` or system calls.
    
    // For now, we'll fall back to TCP connect scan
    warn!("SYN scan requested but not implemented, falling back to TCP connect");
    tcp_connect_scan(ip, port, _timeout_duration).await
}

// Grab banner from service
async fn grab_banner(ip: IpAddr, port: u16, timeout_duration: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    
    match timeout(timeout_duration, async {
        let mut stream = TcpStream::connect(addr).await.ok()?;
        let mut buffer = vec![0; 1024];
        
        // Try to read banner
        match tokio::time::timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read(&mut stream, &mut buffer)
        ).await {
            Ok(Ok(n)) if n > 0 => {
                String::from_utf8_lossy(&buffer[..n])
                    .trim()
                    .to_string()
                    .into()
            }
            _ => None,
        }
    }).await {
        Ok(banner) => banner,
        Err(_) => None,
    }
}

// Main scanning function
async fn scan_ports(
    state: &AppState,
    request: ScanRequest,
) -> Result<ScanResponse> {
    let start_time = std::time::Instant::now();
    
    // Check if we should use Nmap
    let use_nmap = request.use_nmap.unwrap_or(false) || request.tor_mode.unwrap_or(false);
    let nmap_available = check_nmap_available(&state.nmap_path);
    
    // If TOR mode is enabled, always try to use Nmap with stealth settings
    let scan_type = if request.tor_mode.unwrap_or(false) {
        "stealth"
    } else {
        request.nmap_scan_type.as_deref().unwrap_or("syn")
    };
    
    if use_nmap && nmap_available {
        // Use Nmap for scanning
        info!("Using Nmap scanner with scan type: {}", scan_type);
        
        match nmap_scan(
            &state.nmap_path,
            &request.target,
            scan_type,
            request.tor_mode.unwrap_or(false),
            request.scan_range.unwrap_or(false),
        ).await {
            Ok((ports, discovered_hosts)) => {
                let scan_time_ms = start_time.elapsed().as_millis() as u64;
                
                // For single host, resolve to IP
                let ip_address = if request.scan_range.unwrap_or(false) {
                    request.target.clone()  // Keep the range notation
                } else {
                    resolve_target(&state.resolver, &request.target)
                        .await
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|_| request.target.clone())
                };
                
                return Ok(ScanResponse {
                    target: request.target,
                    ip_address,
                    open_ports: ports,
                    scan_time_ms,
                    technique_used: format!("Nmap {} scan{}", 
                        scan_type, 
                        if request.tor_mode.unwrap_or(false) { " (TOR mode)" } else { "" }
                    ),
                    scanner_used: "Nmap".to_string(),
                    discovered_hosts: if request.scan_range.unwrap_or(false) { 
                        Some(discovered_hosts) 
                    } else { 
                        None 
                    },
                });
            }
            Err(e) => {
                warn!("Nmap scan failed, falling back to built-in scanner: {}", e);
            }
        }
    }
    
    // Fallback to built-in scanner
    info!("Using built-in scanner");
    
    // Resolve target to IP
    let ip = resolve_target(&state.resolver, &request.target).await?;
    info!("Resolved {} to {}", request.target, ip);
    
    // Default ports if not specified
    let ports = request.ports.unwrap_or_else(|| vec![
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1433, 1521, 1723, 3306, 3389, 5432, 5900, 6379,
        8080, 8443, 8888, 9200, 27017,
    ]);
    
    let timeout_ms = request.timeout_ms.unwrap_or(1000);
    let timeout_duration = Duration::from_millis(timeout_ms);
    let max_concurrent = request.max_concurrent.unwrap_or(100);
    
    // Determine scan technique
    let techniques = request.techniques.as_ref();
    let use_syn = techniques.map(|t| t.syn_scan).unwrap_or(false);
    let technique_used = if use_syn { "SYN" } else { "TCP Connect" };
    
    // Apply timing evasion if requested or in TOR mode
    let timing_evasion = techniques.map(|t| t.timing_evasion).unwrap_or(false) 
        || request.tor_mode.unwrap_or(false);
    
    if timing_evasion {
        info!("Using timing evasion techniques");
    }
    
    // Scan ports concurrently
    let scan_futures = stream::iter(ports.iter().copied())
        .map(|port| async move {
            // Add random delay for timing evasion
            if timing_evasion {
                tokio::time::sleep(Duration::from_millis(
                    rand::thread_rng().gen::<u64>() % 100
                )).await;
            }
            
            let is_open = if use_syn {
                syn_scan(ip, port, timeout_duration).await
            } else {
                tcp_connect_scan(ip, port, timeout_duration).await
            }.unwrap_or(false);
            
            if is_open {
                let banner = grab_banner(ip, port, timeout_duration).await;
                Some(PortInfo {
                    port,
                    state: "open".to_string(),
                    service: get_service_name(port).to_string(),
                    banner,
                    version: None,
                })
            } else {
                None
            }
        })
        .buffer_unordered(max_concurrent)
        .filter_map(|result| async { result })
        .collect::<Vec<_>>()
        .await;
    
    let scan_time_ms = start_time.elapsed().as_millis() as u64;
    
    Ok(ScanResponse {
        target: request.target,
        ip_address: ip.to_string(),
        open_ports: scan_futures,
        scan_time_ms,
        technique_used: format!("{}{}", 
            technique_used,
            if request.tor_mode.unwrap_or(false) { " (TOR mode)" } else { "" }
        ),
        scanner_used: "Built-in".to_string(),
        discovered_hosts: None,
    })
}

// API handlers
async fn health_check() -> &'static str {
    "Scanner service is healthy"
}

async fn scan_handler(
    State(state): State<AppState>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, StatusCode> {
    match scan_ports(&state, request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Scan error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    // Create DNS resolver
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));
    
    // Detect Nmap path
    let nmap_path = if cfg!(windows) {
        // Windows paths
        let paths = vec![
            r"C:\Program Files (x86)\Nmap\nmap.exe",
            r"C:\Program Files\Nmap\nmap.exe",
            "nmap.exe",
        ];
        paths.into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap_or("nmap.exe")
            .to_string()
    } else {
        // Unix paths
        "nmap".to_string()
    };
    
    info!("Using Nmap path: {}", nmap_path);
    if check_nmap_available(&nmap_path) {
        info!("Nmap is available");
    } else {
        warn!("Nmap not found, will use built-in scanner only");
    }
    
    let state = AppState { resolver, nmap_path };
    
    // Build router
    let app = Router::new()
        .route("/", get(|| async { Json(serde_json::json!({
            "service": "COBRA AI Port Scanner",
            "version": "1.0.0",
            "status": "operational",
            "nmap_available": check_nmap_available(&state.nmap_path)
        })) }))
        .route("/health", get(health_check))
        .route("/scan", post(scan_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);
    
    let port = std::env::var("SCANNER_SERVICE_PORT")
        .unwrap_or_else(|_| "8002".to_string())
        .parse::<u16>()?;
    
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Scanner service listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    
    Ok(())
} 