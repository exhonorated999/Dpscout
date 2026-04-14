// Media file server for streaming large files
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use tauri::http::{header, Request, Response, StatusCode};

type HttpResponse = Response<Vec<u8>>;

// Helper to create response
fn build_response(status: StatusCode, body: Vec<u8>) -> HttpResponse {
    Response::builder()
        .status(status)
        .body(body)
        .unwrap()
}

fn build_response_with_headers(
    status: StatusCode,
    headers: Vec<(&str, String)>,
    body: Vec<u8>,
) -> HttpResponse {
    let mut builder = Response::builder().status(status);
    for (key, value) in headers {
        builder = builder.header(key, value);
    }
    builder.body(body).unwrap()
}

/// Get MIME type from file extension
fn get_mime_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        // Images
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("png") => "image/png",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("bmp") => "image/bmp",
        Some("svg") => "image/svg+xml",
        
        // Videos
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("ogg") | Some("ogv") => "video/ogg",
        Some("avi") => "video/x-msvideo",
        Some("mov") => "video/quicktime",
        Some("m4v") => "video/x-m4v",
        Some("mkv") => "video/x-matroska",
        Some("flv") => "video/x-flv",
        Some("wmv") => "video/x-ms-wmv",
        Some("3gp") => "video/3gpp",
        Some("ts") => "video/mp2t", // MPEG Transport Stream
        Some("mts") => "video/mp2t",
        Some("m2ts") => "video/mp2t",
        
        // Audio
        Some("mp3") => "audio/mpeg",
        Some("wav") => "audio/wav",
        Some("ogg") | Some("oga") => "audio/ogg",
        Some("m4a") => "audio/mp4",
        Some("flac") => "audio/flac",
        Some("aac") => "audio/aac",
        
        _ => "application/octet-stream",
    }
}

/// Parse range header (e.g., "bytes=0-1023")
fn parse_range(range_header: &str, file_size: u64) -> Option<(u64, u64)> {
    let parts: Vec<&str> = range_header.trim_start_matches("bytes=").split('-').collect();
    
    match parts.as_slice() {
        [start, end] if !start.is_empty() && !end.is_empty() => {
            let start = start.parse::<u64>().ok()?;
            let end = end.parse::<u64>().ok()?.min(file_size - 1);
            Some((start, end))
        }
        [start, ""] if !start.is_empty() => {
            let start = start.parse::<u64>().ok()?;
            Some((start, file_size - 1))
        }
        ["", end] if !end.is_empty() => {
            let end = end.parse::<u64>().ok()?;
            let start = file_size.saturating_sub(end);
            Some((start, file_size - 1))
        }
        _ => None,
    }
}

/// Handle media file requests with range support
pub fn handle_media_request(
    request: &Request<Vec<u8>>,
    file_path: &Path,
) -> Result<HttpResponse, Box<dyn std::error::Error>> {
    eprintln!("[Media Server] Serving file: {:?}", file_path);
    
    // Check if file exists
    if !file_path.exists() {
        eprintln!("[Media Server] File not found: {:?}", file_path);
        return Ok(build_response(StatusCode::NOT_FOUND, b"File not found".to_vec()));
    }
    
    // Open file
    let mut file = File::open(file_path)?;
    let metadata = file.metadata()?;
    let file_size = metadata.len();
    let mime_type = get_mime_type(file_path);
    
    eprintln!("[Media Server] File size: {} bytes, MIME: {}", file_size, mime_type);
    
    // Check for range request
    let range_header = request.headers().get("range").and_then(|v| v.to_str().ok());
    
    if let Some(range_str) = range_header {
        eprintln!("[Media Server] Range request: {}", range_str);
        
        // Parse range
        if let Some((start, end)) = parse_range(range_str, file_size) {
            let content_length = end - start + 1;
            
            // Seek to start position
            file.seek(SeekFrom::Start(start))?;
            
            // Read the requested range
            let mut buffer = vec![0u8; content_length as usize];
            file.read_exact(&mut buffer)?;
            
            eprintln!("[Media Server] Serving range: {}-{}/{}", start, end, file_size);
            
            // Return partial content response
            return Ok(build_response_with_headers(
                StatusCode::PARTIAL_CONTENT,
                vec![
                    (header::CONTENT_TYPE.as_str(), mime_type.to_string()),
                    (header::CONTENT_LENGTH.as_str(), content_length.to_string()),
                    (
                        header::CONTENT_RANGE.as_str(),
                        format!("bytes {}-{}/{}", start, end, file_size),
                    ),
                    (header::ACCEPT_RANGES.as_str(), "bytes".to_string()),
                    (header::ACCESS_CONTROL_ALLOW_ORIGIN.as_str(), "*".to_string()),
                ],
                buffer,
            ));
        }
    }
    
    // No range request - serve entire file
    eprintln!("[Media Server] Serving entire file");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    
    Ok(build_response_with_headers(
        StatusCode::OK,
        vec![
            (header::CONTENT_TYPE.as_str(), mime_type.to_string()),
            (header::CONTENT_LENGTH.as_str(), file_size.to_string()),
            (header::ACCEPT_RANGES.as_str(), "bytes".to_string()),
            (header::ACCESS_CONTROL_ALLOW_ORIGIN.as_str(), "*".to_string()),
        ],
        buffer,
    ))
}

/// Tauri command to get file as base64 (for smaller files)
#[tauri::command]
pub async fn get_file_as_base64(path: String) -> Result<String, String> {
    eprintln!("[Media Server] Converting file to base64: {}", path);
    
    let file_path = Path::new(&path);
    
    if !file_path.exists() {
        return Err(format!("File not found: {}", path));
    }
    
    let mut file = File::open(file_path)
        .map_err(|e| format!("Failed to open file: {}", e))?;
    
    let metadata = file.metadata()
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    
    // Limit to 50MB for base64 encoding
    if metadata.len() > 50 * 1024 * 1024 {
        return Err("File too large for base64 encoding (max 50MB)".to_string());
    }
    
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    
    let mime_type = get_mime_type(file_path);
    let base64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &buffer);
    
    Ok(format!("data:{};base64,{}", mime_type, base64))
}

/// Tauri command to check if file exists and get basic info
#[tauri::command]
pub async fn get_media_file_info(path: String) -> Result<MediaFileInfo, String> {
    let file_path = Path::new(&path);
    
    if !file_path.exists() {
        return Err(format!("File not found: {}", path));
    }
    
    let metadata = std::fs::metadata(file_path)
        .map_err(|e| format!("Failed to get file metadata: {}", e))?;
    
    Ok(MediaFileInfo {
        path: path.clone(),
        size: metadata.len(),
        mime_type: get_mime_type(file_path).to_string(),
        exists: true,
    })
}

#[derive(serde::Serialize)]
pub struct MediaFileInfo {
    pub path: String,
    pub size: u64,
    pub mime_type: String,
    pub exists: bool,
}
