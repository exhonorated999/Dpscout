// PDF Report Generation using printpdf

use super::{ReportPayload, ReportScope, generate_report_filename};
use printpdf::*;
use std::error::Error;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

const FONT_SIZE_TITLE: f32 = 24.0;
const FONT_SIZE_HEADING: f32 = 16.0;
const FONT_SIZE_SUBHEADING: f32 = 14.0;
const FONT_SIZE_BODY: f32 = 11.0;
const FONT_SIZE_SMALL: f32 = 9.0;
const FONT_SIZE_LABEL: f32 = 10.0;

const LINE_HEIGHT_BODY: f32 = 5.0;
const LINE_HEIGHT_SECTION: f32 = 8.0;
const PAGE_MARGIN: f32 = 20.0;
const PAGE_WIDTH: f32 = 210.0; // A4
const PAGE_HEIGHT: f32 = 297.0; // A4
const BOTTOM_MARGIN: f32 = 30.0;

// Helper functions for creating colors
fn color_primary() -> Color {
    // Datapilot Scout blue: #6B8AFF
    Color::Rgb(Rgb::new(0.42, 0.54, 1.0, None))
}

fn color_primary_dark() -> Color {
    // Darker blue for backgrounds: #4169e1
    Color::Rgb(Rgb::new(0.255, 0.412, 0.882, None))
}

fn color_section_header() -> Color {
    // Dark gray for section headers - good visibility
    Color::Rgb(Rgb::new(0.2, 0.2, 0.2, None))
}

fn color_accent() -> Color {
    // Kept for backward compatibility
    color_section_header()
}

fn color_text() -> Color {
    Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None))
}

fn color_gray() -> Color {
    Color::Rgb(Rgb::new(0.5, 0.5, 0.5, None))
}

fn color_light_gray() -> Color {
    Color::Rgb(Rgb::new(0.7, 0.7, 0.7, None))
}

fn color_light_blue_bg() -> Color {
    // Light blue background for section boxes
    Color::Rgb(Rgb::new(0.93, 0.95, 1.0, None))
}

fn color_critical() -> Color {
    // Red for critical/high severity
    Color::Rgb(Rgb::new(0.9, 0.2, 0.2, None))
}

fn color_warning() -> Color {
    // Orange for medium severity
    Color::Rgb(Rgb::new(1.0, 0.6, 0.0, None))
}

fn color_success() -> Color {
    // Green for low severity/success
    Color::Rgb(Rgb::new(0.2, 0.7, 0.3, None))
}

// PDF Context for pagination
struct PdfContext<'a> {
    doc: &'a PdfDocumentReference,
    page_index: PdfPageIndex,
    layer_index: PdfLayerIndex,
    y_position: Mm,
    font: &'a IndirectFontRef,
    font_bold: &'a IndirectFontRef,
}

impl<'a> PdfContext<'a> {
    fn current_layer(&self) -> PdfLayerReference {
        self.doc.get_page(self.page_index).get_layer(self.layer_index)
    }
    
    fn check_page_break(&mut self, required_space: f32) {
        if self.y_position.0 < BOTTOM_MARGIN + required_space {
            add_new_page(self);
        }
    }
}

fn add_new_page(ctx: &mut PdfContext) {
    let (new_page, new_layer) = ctx.doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Content");
    ctx.page_index = new_page;
    ctx.layer_index = new_layer;
    ctx.y_position = Mm(PAGE_HEIGHT - PAGE_MARGIN);
}

// Helper function to draw a filled rectangle
fn draw_filled_rect(layer: &PdfLayerReference, x: Mm, y: Mm, width: Mm, height: Mm) {
    use printpdf::{Point, Polygon};
    use printpdf::path::{PaintMode, WindingOrder};
    
    // Draw filled rectangle using polygon
    let points = vec![
        (Point::new(x, y), false),
        (Point::new(x + width, y), false),
        (Point::new(x + width, y + height), false),
        (Point::new(x, y + height), false),
    ];
    
    let polygon = Polygon {
        rings: vec![points],
        mode: PaintMode::FillStroke,
        winding_order: WindingOrder::NonZero,
    };
    
    layer.add_polygon(polygon);
}

// Helper function to draw a colored section box (simplified - using lines)
fn draw_section_box(_layer: &PdfLayerReference, _x: Mm, _y: Mm, _width: Mm, _height: Mm, _color: Color) {
    // Simplified for now - printpdf shapes API is complex
    // Visual enhancement will be primarily through colors and text
}

// Helper function to draw a colored left border bar
fn draw_left_border(layer: &PdfLayerReference, x: Mm, y: Mm, height: Mm, color: Color) {
    layer.set_fill_color(color);
    draw_filled_rect(layer, x, y - height, Mm(3.0), height);
}

// ========== FACE PAGE ==========
fn draw_face_page(ctx: &mut PdfContext, payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    let mut y = ctx.y_position;
    
    // Title - Datapilot Scout branding (matching logo)
    layer.set_fill_color(color_text());
    layer.use_text("DATAPILOT", FONT_SIZE_TITLE + 8.0, left_margin, y, ctx.font_bold);
    y -= Mm(12.0);
    
    layer.set_fill_color(color_primary());
    layer.use_text("SCOUT", FONT_SIZE_TITLE + 8.0, left_margin, y, ctx.font_bold);
    y -= Mm(10.0);
    
    // "POWERED BY PROJECT HINDSIGHT" subtitle
    layer.set_fill_color(color_gray());
    layer.use_text("POWERED BY", FONT_SIZE_SMALL, left_margin, y, ctx.font);
    y -= Mm(5.0);
    
    layer.set_fill_color(color_primary());
    layer.use_text("PROJECT HINDSIGHT", FONT_SIZE_SUBHEADING, left_margin, y, ctx.font_bold);
    y -= Mm(10.0);
    
    // Separator line
    layer.set_fill_color(color_primary_dark());
    layer.use_text("_____________________________________________", FONT_SIZE_BODY, left_margin, y, ctx.font);
    y -= Mm(8.0);
    
    layer.set_fill_color(color_gray());
    layer.use_text("Digital Forensic Triage Report", FONT_SIZE_HEADING, left_margin, y, ctx.font);
    y -= Mm(20.0);
    
    // Case Information Section with blue header box
    let box_height = Mm(8.0);
    layer.set_fill_color(color_light_blue_bg());
    draw_filled_rect(&layer, left_margin, y - box_height, Mm(170.0), box_height);
    
    // Draw text AFTER background box so it appears on top
    layer.set_fill_color(color_primary());
    layer.use_text("CASE INFORMATION", FONT_SIZE_SUBHEADING, left_margin + Mm(3.0), y - Mm(5.0), ctx.font_bold);
    y -= Mm(13.0);
    
    layer.set_fill_color(color_text());
    let box_margin = left_margin + Mm(5.0); // Indent inside the box
    y = draw_info_field(&layer, "Case Number:", &payload.metadata.case_number, box_margin, y, ctx.font_bold, ctx.font);
    y = draw_info_field(&layer, "Assigned Detective:", &payload.metadata.assigned_detective, box_margin, y, ctx.font_bold, ctx.font);
    y = draw_info_field(&layer, "Report Generated:", &payload.metadata.generated_date, box_margin, y, ctx.font_bold, ctx.font);
    
    if let Some(ref device) = payload.metadata.device_name {
        y = draw_info_field(&layer, "Device Name:", device, box_margin, y, ctx.font_bold, ctx.font);
    }
    
    if let Some(ref os) = payload.metadata.operating_system {
        y = draw_info_field(&layer, "Operating System:", os, box_margin, y, ctx.font_bold, ctx.font);
    }
    
    if let Some(ref drive) = payload.metadata.drive_scanned {
        y = draw_info_field(&layer, "Drive Scanned:", drive, box_margin, y, ctx.font_bold, ctx.font);
    }
    
    y -= Mm(15.0);
    
    // Scan Parameters Section with colored header box
    layer.set_fill_color(color_light_blue_bg());
    draw_filled_rect(&layer, left_margin, y - Mm(8.0), Mm(170.0), Mm(8.0));
    
    // Draw text AFTER background
    layer.set_fill_color(color_primary());
    layer.use_text("SCAN PARAMETERS", FONT_SIZE_SUBHEADING, left_margin + Mm(3.0), y - Mm(5.0), ctx.font_bold);
    y -= Mm(15.0); // Increased spacing to match CASE INFORMATION
    
    if let Some(ref params) = payload.metadata.scan_parameters {
        let mut scan_types = Vec::new();
        if params.applications_scanned {
            scan_types.push("Applications");
        }
        if params.browser_history_scanned {
            scan_types.push("Browser History");
        }
        if params.keyword_search_performed {
            scan_types.push("Keyword Search");
        }
        if params.hash_matching_performed {
            scan_types.push("Hash Matching");
        }
        if params.media_scan_performed {
            scan_types.push("Media Scan");
        }
        if params.intrusion_detection_performed {
            scan_types.push("Intrusion Detection");
        }
        if params.deleted_media_scan_performed {
            scan_types.push("Deleted Media Detection");
        }
        
        y = draw_info_field(&layer, "Scan Categories:", &scan_types.join(", "), left_margin, y, ctx.font_bold, ctx.font);
    }
    
    if let Some(ref duration) = payload.metadata.scan_duration {
        y = draw_info_field(&layer, "Scan Duration:", duration, left_margin, y, ctx.font_bold, ctx.font);
    }
    
    if let Some(start_time) = &payload.metadata.triage_start_time {
        y = draw_info_field(&layer, "Scan Start Time:", start_time, left_margin, y, ctx.font_bold, ctx.font);
    }
    
    if let Some(end_time) = &payload.metadata.triage_end_time {
        y = draw_info_field(&layer, "Scan End Time:", end_time, left_margin, y, ctx.font_bold, ctx.font);
    }
    
    y -= Mm(15.0);
    
    // Findings Summary with colored header box
    let total_flags = payload.metadata.total_flags.unwrap_or(payload.flagged_item_ids.len() as u32);
    let header_color = if total_flags > 0 { 
        // Light orange/red background for flagged items
        Color::Rgb(Rgb::new(1.0, 0.95, 0.9, None))
    } else { 
        color_light_blue_bg()
    };
    layer.set_fill_color(header_color);
    draw_filled_rect(&layer, left_margin, y - Mm(8.0), Mm(170.0), Mm(8.0));
    
    // Draw text AFTER background
    layer.set_fill_color(color_primary());
    layer.use_text("FINDINGS SUMMARY", FONT_SIZE_SUBHEADING, left_margin + Mm(3.0), y - Mm(5.0), ctx.font_bold);
    y -= Mm(15.0); // Increased spacing to match CASE INFORMATION
    
    layer.set_fill_color(color_text());
    y = draw_info_field(&layer, "Total Flagged Items:", &total_flags.to_string(), left_margin, y, ctx.font_bold, ctx.font);
    
    let scope_text = match payload.scope {
        ReportScope::Flagged => "Flagged Evidence Only",
        ReportScope::All => "All Scan Results",
    };
    y = draw_info_field(&layer, "Report Scope:", scope_text, left_margin, y, ctx.font_bold, ctx.font);
    
    ctx.y_position = y;
    Ok(())
}

// ========== FLAGGED EVIDENCE SECTIONS ==========
fn draw_flagged_evidence_sections(ctx: &mut PdfContext, payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    
    // Debug logging
    eprintln!("=== PDF GENERATION DEBUG ===");
    eprintln!("Flagged item IDs count: {}", payload.flagged_item_ids.len());
    eprintln!("Flagged item IDs: {:?}", payload.flagged_item_ids);
    
    // DEBUG: Print the ENTIRE payload as JSON to see what we're actually getting
    eprintln!("=== FULL PAYLOAD DUMP ===");
    if let Ok(json) = serde_json::to_string_pretty(&payload) {
        eprintln!("{}", json);
    }
    eprintln!("=== END PAYLOAD DUMP ===");
    
    // Check for isFlagged in apps
    if let Some(apps) = payload.all_data.apps.as_array() {
        let flagged_apps = apps.iter().filter(|a| a.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
        eprintln!("Apps with isFlagged=true: {}", flagged_apps);
    }
    
    // Check for isFlagged in media
    if let Some(media) = payload.all_data.csam.as_array() {
        let flagged_media = media.iter().filter(|m| m.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
        eprintln!("Media with isFlagged=true: {}", flagged_media);
    }
    
    // Check for isFlagged in keywords
    if let Some(keywords) = payload.all_data.keywords.as_array() {
        let flagged_keywords = keywords.iter().filter(|k| k.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
        eprintln!("Keywords with isFlagged=true: {}", flagged_keywords);
    }
    
    // Check browser data structure
    if let Some(browsers) = payload.all_data.browsers.as_array() {
        eprintln!("Browser data count: {}", browsers.len());
        for (idx, browser) in browsers.iter().enumerate() {
            eprintln!("Browser {}: {:?}", idx, browser.as_object().map(|o| o.keys().collect::<Vec<_>>()));
            
            if let Some(history) = browser.get("history").and_then(|h| h.as_array()) {
                let flagged_count = history.iter().filter(|h| {
                    h.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false) ||
                    h.get("flags").and_then(|f| f.as_array()).map(|arr| !arr.is_empty()).unwrap_or(false)
                }).count();
                eprintln!("  History items: {}, flagged: {}", history.len(), flagged_count);
            }
            
            if let Some(downloads) = browser.get("downloads").and_then(|d| d.as_array()) {
                let flagged_count = downloads.iter().filter(|d| {
                    d.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false) ||
                    d.get("flags").and_then(|f| f.as_array()).map(|arr| !arr.is_empty()).unwrap_or(false)
                }).count();
                eprintln!("  Download items: {}, flagged: {}", downloads.len(), flagged_count);
            }
        }
    }
    
    eprintln!("=========================");
    
    // Section title - changes based on scope
    layer.set_fill_color(color_primary());
    let section_title = match payload.scope {
        ReportScope::Flagged => "FLAGGED EVIDENCE DETAILS",
        ReportScope::All => "SCAN RESULTS - ALL EVIDENCE",
    };
    layer.use_text(section_title, FONT_SIZE_HEADING, left_margin, ctx.y_position, ctx.font_bold);
    ctx.y_position -= Mm(12.0);
    
    layer.set_fill_color(color_text());
    
    // Only check for empty if scope is Flagged
    if payload.scope == ReportScope::Flagged && payload.flagged_item_ids.is_empty() {
        layer.use_text("No items were flagged during this triage.", FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(10.0);
        return Ok(());
    }
    
    // Applications - Always show section if apps were scanned
    if let Some(apps) = payload.all_data.apps.as_array() {
        if !apps.is_empty() {
            add_new_page(ctx);
            draw_flagged_apps(ctx, apps, payload)?;
        }
    }
    
    // Media Files - Always show section if media scan was performed
    if let Some(media) = payload.all_data.csam.as_array() {
        if !media.is_empty() {
            eprintln!("Drawing media section with {} items...", media.len());
            add_new_page(ctx);
            draw_flagged_media(ctx, media, payload)?;
        }
    }
    
    // CSAM Hash Matches - Show hash scan hits (Android hash matches, USB hash matches)
    if let Some(hash_matches) = payload.all_data.hash_matches.as_array() {
        if !hash_matches.is_empty() {
            eprintln!("Drawing CSAM hash matches section with {} items...", hash_matches.len());
            add_new_page(ctx);
            draw_flagged_hash_matches(ctx, hash_matches, payload)?;
        }
    }
    
    // Keywords - Always show section if keyword search was performed
    if let Some(keywords) = payload.all_data.keywords.as_array() {
        if !keywords.is_empty() {
            add_new_page(ctx);
            draw_flagged_keywords(ctx, keywords, payload)?;
        }
    }
    
    // Browser Data - Always show section if browsers were scanned
    if let Some(browsers) = payload.all_data.browsers.as_array() {
        // Check if there's ANY browser data at all
        let has_data = !browsers.is_empty() && browsers.iter().any(|browser| {
            let has_history = browser.get("history").and_then(|h| h.as_array()).map(|arr| !arr.is_empty()).unwrap_or(false);
            let has_downloads = browser.get("downloads").and_then(|d| d.as_array()).map(|arr| !arr.is_empty()).unwrap_or(false);
            let has_creds = browser.get("credentials").and_then(|c| c.as_array()).map(|arr| !arr.is_empty()).unwrap_or(false);
            has_history || has_downloads || has_creds
        });
        
        if has_data {
            eprintln!("Drawing browser section...");
            add_new_page(ctx);
            draw_flagged_browsers(ctx, browsers, payload)?;
        } else {
            eprintln!("Skipping browser section - no browser data found");
        }
    }
    
    // Intrusion Events - Always show section if intrusion detection was performed
    if let Some(intrusion) = payload.all_data.intrusion.as_object() {
        // Show if there are any events at all
        let has_events = if let Some(events) = intrusion.get("events").and_then(|e| e.as_array()) {
            !events.is_empty()
        } else {
            false
        };
        
        if has_events {
            add_new_page(ctx);
            draw_flagged_intrusion(ctx, intrusion, payload)?;
        }
    }
    
    // Deleted Media (Unallocated Space) - show if a deleted-media scan ran on any drive
    if let Some(drives) = payload.all_data.deleted_media.as_array() {
        let has_results = drives.iter().any(|d| {
            d.get("summary").map(|s| !s.is_null()).unwrap_or(false)
                || d.get("error").and_then(|e| e.as_str()).map(|s| !s.is_empty()).unwrap_or(false)
        });
        if has_results {
            add_new_page(ctx);
            draw_deleted_media(ctx, drives, payload)?;
        }
    }
    
    Ok(())
}

fn draw_flagged_apps(ctx: &mut PdfContext, apps: &[serde_json::Value], payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    // Filter based on scope
    let items_to_show: Vec<(usize, &serde_json::Value)> = match payload.scope {
        ReportScope::All => {
            // Show ALL apps
            apps.iter().enumerate().collect()
        }
        ReportScope::Flagged => {
            // Filter for flagged apps only (user-flagged via UI)
            apps.iter()
                .enumerate()
                .filter(|(idx, app)| {
                    let is_flagged = app.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false);
                    let in_flagged_list = payload.flagged_item_ids.iter().any(|id| {
                        id == &format!("app-{}", idx)
                    });
                    is_flagged || in_flagged_list
                })
                .collect()
        }
    };
    
    if items_to_show.is_empty() {
        return Ok(());
    }
    
    ctx.check_page_break(30.0);
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    
    // Section header with colored left border
    draw_left_border(&layer, left_margin, ctx.y_position, Mm(6.0), color_warning());
    layer.set_fill_color(color_primary());
    let header_text = match payload.scope {
        ReportScope::All => format!("APPLICATIONS ({} total)", items_to_show.len()),
        ReportScope::Flagged => format!("APPLICATIONS ({} flagged)", items_to_show.len()),
    };
    layer.use_text(&header_text, FONT_SIZE_SUBHEADING, left_margin + Mm(5.0), ctx.y_position, ctx.font_bold);
    ctx.y_position -= Mm(18.0); // Increased spacing to give more room
    
    layer.set_fill_color(color_text());
    
    for (idx, app) in items_to_show {
        ctx.check_page_break(25.0);
        let layer = ctx.current_layer();
        
        let name = app.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let category = app.get("category").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let install_path = app.get("install_path").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let install_date = app.get("install_date").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let version = app.get("version").and_then(|v| v.as_str()).unwrap_or("Unknown");
        
        // App name (bold)
        layer.use_text(&format!("{}. {}", idx + 1, name), FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font_bold);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // Category
        layer.set_fill_color(color_gray());
        layer.use_text(&format!("   Category: {}", category), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // Install path (wrapped for long paths)
        draw_wrapped_text(&layer, &format!("   Location: {}", install_path), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
        
        // Install date and version
        layer.use_text(&format!("   Installed: {} | Version: {}", install_date, version), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // Show flags if present
        if let Some(flags) = app.get("flags").and_then(|f| f.as_array()) {
            if !flags.is_empty() {
                layer.set_fill_color(color_critical());
                let flags_str: Vec<String> = flags.iter()
                    .filter_map(|f| f.as_str().map(|s| s.to_string()))
                    .collect();
                layer.use_text(&format!("   ⚠ FLAGS: {}", flags_str.join(", ")), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
            }
        }
        
        // Show risk level if present
        if let Some(risk) = app.get("riskLevel").and_then(|r| r.as_str()) {
            let risk_color = match risk {
                "High" => color_critical(),
                "Medium" => color_warning(),
                _ => color_success(),
            };
            layer.set_fill_color(risk_color);
            layer.use_text(&format!("   Risk Level: {}", risk), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
            ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        }
        
        ctx.y_position -= Mm(LINE_HEIGHT_SECTION - LINE_HEIGHT_BODY);
        layer.set_fill_color(color_text());
    }
    
    ctx.y_position -= Mm(5.0);
    Ok(())
}

fn draw_flagged_media(ctx: &mut PdfContext, media: &[serde_json::Value], payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    let show_all = payload.scope == ReportScope::All;
    
    // Filter based on scope
    let items: Vec<(usize, &serde_json::Value)> = if show_all {
        media.iter().enumerate().collect()
    } else {
        media.iter()
            .enumerate()
            .filter(|(idx, m)| {
                // (a) Explicitly tagged by user (clicked "Tag as Evidence" / "Flag")
                let is_flagged = m.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false);
                // (b) In flagged_item_ids list (user-selected items) — exact match
                let target_id = format!("media-{}", idx);
                let in_flagged_list = payload.flagged_item_ids.iter().any(|id| id == &target_id);
                // (c) Auto-flagged by the scanner (e.g. Project VIC hash hit on iOS AFC
                //     items). The user never has to manually tag these — they MUST
                //     show up in a "Flagged Only" report. Detect by non-empty flags[].
                let has_auto_flags = m.get("flags")
                    .and_then(|f| f.as_array())
                    .map(|arr| !arr.is_empty())
                    .unwrap_or(false);
                is_flagged || in_flagged_list || has_auto_flags
            })
            .collect()
    };
    
    ctx.check_page_break(30.0);
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    
    // Section header with colored left border
    draw_left_border(&layer, left_margin, ctx.y_position, Mm(6.0), color_critical());
    layer.set_fill_color(color_primary());
    let section_label = if show_all {
        format!("MEDIA FILES ({} items)", items.len())
    } else {
        format!("MEDIA FILES ({} flagged)", items.len())
    };
    layer.use_text(&section_label, FONT_SIZE_SUBHEADING, left_margin + Mm(5.0), ctx.y_position, ctx.font_bold);
    ctx.y_position -= Mm(18.0); // Increased spacing to give more room
    
    layer.set_fill_color(color_text());
    
    if items.is_empty() {
        let msg = if show_all {
            "No media files found."
        } else {
            "No flagged media files."
        };
        layer.use_text(msg, FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(10.0);
        return Ok(());
    }
    
    for (idx, media_item) in items {
        ctx.check_page_break(25.0);
        let layer = ctx.current_layer();
        
        let file_name = media_item.get("fileName").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let file_path = media_item.get("filePath").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let date_created = media_item.get("dateCreated").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let date_accessed = media_item.get("dateAccessed").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let file_size = media_item.get("fileSize").and_then(|v| v.as_u64()).unwrap_or(0);
        
        // File name (bold)
        layer.use_text(&format!("{}. {}", idx + 1, file_name), FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font_bold);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // File path (wrapped for long paths)
        layer.set_fill_color(color_gray());
        draw_wrapped_text(&layer, &format!("   Location: {}", file_path), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
        
        // Dates
        layer.use_text(&format!("   Created: {} | Last Accessed: {}", date_created, date_accessed), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // File size
        layer.use_text(&format!("   Size: {} bytes", format_number(file_size)), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // Flags
        if let Some(flags) = media_item.get("flags").and_then(|f| f.as_array()) {
            for flag in flags {
                // MediaFlag serializes with rename_all = "camelCase" → field is
                // `flagType`. Older payloads used `type` — fall back for forward
                // compatibility.
                let flag_type = flag.get("flagType")
                    .or_else(|| flag.get("type"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let reason = flag.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                let severity = flag.get("severity").and_then(|v| v.as_str()).unwrap_or("unknown");
                
                layer.set_fill_color(color_primary());
                layer.use_text(&format!("   ⚠ [{}] {}: {}", severity.to_uppercase(), flag_type, reason), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
            }
        }
        
        ctx.y_position -= Mm(LINE_HEIGHT_SECTION - LINE_HEIGHT_BODY);
        layer.set_fill_color(color_text());
    }
    
    ctx.y_position -= Mm(5.0);
    Ok(())
}

fn draw_flagged_hash_matches(ctx: &mut PdfContext, hash_matches: &[serde_json::Value], payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    let show_all = payload.scope == ReportScope::All;
    
    // Filter based on scope
    let items: Vec<(usize, &serde_json::Value)> = if show_all {
        hash_matches.iter().enumerate().collect()
    } else {
        hash_matches.iter()
            .enumerate()
            .filter(|(idx, m)| {
                let is_flagged = m.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false);
                let file_path = m.get("filePath").and_then(|v| v.as_str()).unwrap_or("");
                let in_flagged_list = payload.flagged_item_ids.iter().any(|id| {
                    id == &format!("hash-match-{}-{}", file_path, idx)
                });
                is_flagged || in_flagged_list
            })
            .collect()
    };
    
    ctx.check_page_break(30.0);
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    
    // Section header with colored left border
    draw_left_border(&layer, left_margin, ctx.y_position, Mm(6.0), color_critical());
    layer.set_fill_color(color_primary());
    let section_label = if show_all {
        format!("CSAM HASH MATCHES ({} hits)", items.len())
    } else {
        format!("CSAM HASH MATCHES ({} flagged)", items.len())
    };
    layer.use_text(&section_label, FONT_SIZE_SUBHEADING, left_margin + Mm(5.0), ctx.y_position, ctx.font_bold);
    ctx.y_position -= Mm(18.0);
    
    layer.set_fill_color(color_text());
    
    if items.is_empty() {
        let msg = if show_all {
            "No CSAM hash matches detected."
        } else {
            "No flagged CSAM hash matches."
        };
        layer.use_text(msg, FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(10.0);
        return Ok(());
    }
    
    for (idx, item) in items {
        ctx.check_page_break(30.0);
        let layer = ctx.current_layer();
        
        let file_name = item.get("fileName").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let file_path = item.get("filePath").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let hash_type = item.get("hashType").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let matched_hash = item.get("matchedHash").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let list_source = item.get("listSource").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let description = item.get("description").and_then(|v| v.as_str()).unwrap_or("");
        let severity = item.get("severity").and_then(|v| v.as_str()).unwrap_or("Critical");
        let file_size = item.get("fileSize").and_then(|v| v.as_u64()).unwrap_or(0);
        
        // File name (bold) with severity indicator
        layer.set_fill_color(color_critical());
        layer.use_text(&format!("{}. ⚠ {} [{}]", idx + 1, file_name, severity.to_uppercase()), FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font_bold);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // File path
        layer.set_fill_color(color_gray());
        draw_wrapped_text(&layer, &format!("   Location: {}", file_path), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
        
        // Hash info
        layer.set_fill_color(color_text());
        layer.use_text(&format!("   {}: {}", hash_type, matched_hash), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // Source database
        layer.use_text(&format!("   Source: {}", list_source), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // Description (if any)
        if !description.is_empty() {
            layer.set_fill_color(color_primary());
            layer.use_text(&format!("   Description: {}", description), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
            ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        }
        
        // File size
        if file_size > 0 {
            layer.set_fill_color(color_gray());
            layer.use_text(&format!("   Size: {} bytes", format_number(file_size)), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
            ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        }
        
        ctx.y_position -= Mm(LINE_HEIGHT_SECTION - LINE_HEIGHT_BODY);
        layer.set_fill_color(color_text());
    }
    
    ctx.y_position -= Mm(5.0);
    Ok(())
}

fn draw_flagged_keywords(ctx: &mut PdfContext, keywords: &[serde_json::Value], payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    let show_all = payload.scope == ReportScope::All;
    
    // Filter based on scope
    let items: Vec<(usize, &serde_json::Value)> = if show_all {
        keywords.iter().enumerate().collect()
    } else {
        keywords.iter()
            .enumerate()
            .filter(|(idx, k)| {
                let is_flagged = k.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false);
                let in_flagged_list = payload.flagged_item_ids.iter().any(|id| id.starts_with("keyword-") && id.contains(&format!("-{}", idx)));
                is_flagged || in_flagged_list
            })
            .collect()
    };
    
    ctx.check_page_break(30.0);
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    
    // Section header with colored left border
    draw_left_border(&layer, left_margin, ctx.y_position, Mm(6.0), color_warning());
    layer.set_fill_color(color_primary());
    let section_label = if show_all {
        format!("KEYWORD MATCHES ({} items)", items.len())
    } else {
        format!("KEYWORD MATCHES ({} flagged)", items.len())
    };
    layer.use_text(&section_label, FONT_SIZE_SUBHEADING, left_margin + Mm(5.0), ctx.y_position, ctx.font_bold);
    ctx.y_position -= Mm(18.0); // Increased spacing to give more room
    
    layer.set_fill_color(color_text());
    
    if items.is_empty() {
        let msg = if show_all {
            "No keyword matches found."
        } else {
            "No flagged keyword matches."
        };
        layer.use_text(msg, FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(10.0);
        return Ok(());
    }
    
    for (match_idx, keyword_match) in items {
        ctx.check_page_break(15.0);
        let layer = ctx.current_layer();
        
        // Extract data from KeywordMatch structure
        let file_path = keyword_match.get("filePath").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let file_name = keyword_match.get("fileName").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let match_locations = keyword_match.get("matchLocations").and_then(|v| v.as_array());
        
        // Header for this file
        layer.set_fill_color(color_primary());
        layer.use_text(&format!("{}. File: {}", match_idx + 1, file_name), FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font_bold);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        // File path (wrapped for long paths)
        layer.set_fill_color(color_gray());
        draw_wrapped_text(&layer, &format!("   Path: {}", file_path), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
        
        // Process each match location
        if let Some(locations) = match_locations {
            for location in locations {
                let keyword = location.get("keyword").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let match_type = location.get("location").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let context = location.get("context").and_then(|v| v.as_str()).unwrap_or("");
                
                // Keyword and location type
                layer.set_fill_color(color_accent());
                layer.use_text(&format!("   • Keyword: \"{}\" (found in {})", keyword, match_type), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                
                // Context if available
                if !context.is_empty() {
                    layer.set_fill_color(color_gray());
                    let truncated_context = if context.len() > 100 {
                        format!("{}...", &context[..100])
                    } else {
                        context.to_string()
                    };
                    layer.use_text(&format!("     Context: {}", truncated_context), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                    ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                }
            }
        }
        
        ctx.y_position -= Mm(LINE_HEIGHT_SECTION - LINE_HEIGHT_BODY);
        layer.set_fill_color(color_text());
    }
    
    ctx.y_position -= Mm(5.0);
    Ok(())
}

fn draw_flagged_browsers(ctx: &mut PdfContext, browsers: &[serde_json::Value], payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    // Collect browser items based on scope (all or flagged only)
    let mut items: Vec<(String, String, &serde_json::Value)> = Vec::new();
    
    let show_all = payload.scope == ReportScope::All;
    
    for browser in browsers {
        // Try multiple field name variations
        let browser_name = browser.get("browserName")
            .or_else(|| browser.get("browser"))
            .or_else(|| browser.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown Browser");
        let profile = browser.get("profileName")
            .or_else(|| browser.get("profile"))
            .and_then(|v| v.as_str())
            .unwrap_or("Default");
        
        eprintln!("Processing browser: {} ({}) - show_all={}", browser_name, profile, show_all);
        
        // History
        if let Some(history) = browser.get("history").and_then(|h| h.as_array()) {
            eprintln!("  Checking {} history items", history.len());
            for (idx, item) in history.iter().enumerate() {
                let should_include = if show_all {
                    true
                } else {
                    let is_flagged = item.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false);
                    let in_list = payload.flagged_item_ids.iter().any(|id| {
                        id == &format!("browser-history-{}-{}", browser_name, idx)
                    });
                    is_flagged || in_list
                };
                
                if should_include {
                    items.push(("History".to_string(), format!("{} ({})", browser_name, profile), item));
                }
            }
        }
        
        // Downloads
        if let Some(downloads) = browser.get("downloads").and_then(|d| d.as_array()) {
            for (idx, item) in downloads.iter().enumerate() {
                let should_include = if show_all {
                    true
                } else {
                    let is_flagged = item.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false);
                    let in_list = payload.flagged_item_ids.iter().any(|id| {
                        id == &format!("browser-download-{}-{}", browser_name, idx)
                    });
                    is_flagged || in_list
                };
                
                if should_include {
                    items.push(("Download".to_string(), format!("{} ({})", browser_name, profile), item));
                }
            }
        }
        
        // Credentials
        if let Some(creds) = browser.get("credentials").and_then(|c| c.as_array()) {
            for (idx, item) in creds.iter().enumerate() {
                let should_include = if show_all {
                    true
                } else {
                    let is_flagged = item.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false);
                    let in_list = payload.flagged_item_ids.iter().any(|id| {
                        id == &format!("browser-credential-{}-{}", browser_name, idx)
                    });
                    is_flagged || in_list
                };
                
                if should_include {
                    items.push(("Credential".to_string(), format!("{} ({})", browser_name, profile), item));
                }
            }
        }
    }
    
    eprintln!("Total browser items collected: {}", items.len());
    
    ctx.check_page_break(30.0);
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    
    // Section header with colored left border
    draw_left_border(&layer, left_margin, ctx.y_position, Mm(6.0), color_success());
    layer.set_fill_color(color_primary());
    let section_label = if show_all {
        format!("BROWSER DATA ({} items)", items.len())
    } else {
        format!("BROWSER DATA ({} flagged)", items.len())
    };
    layer.use_text(&section_label, FONT_SIZE_SUBHEADING, left_margin + Mm(5.0), ctx.y_position, ctx.font_bold);
    ctx.y_position -= Mm(18.0); // Increased spacing to give more room
    
    layer.set_fill_color(color_text());
    
    if items.is_empty() {
        let msg = if show_all {
            "No browser data found."
        } else {
            "No flagged browser items."
        };
        layer.use_text(msg, FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(10.0);
        return Ok(());
    }
    
    for (idx, (item_type, browser_info, item)) in items.iter().enumerate() {
        ctx.check_page_break(20.0);
        let layer = ctx.current_layer();
        
        // Item header
        layer.use_text(&format!("{}. {} - {}", idx + 1, item_type, browser_info), FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font_bold);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        
        layer.set_fill_color(color_gray());
        
        match item_type.as_str() {
            "History" => {
                let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let title = item.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let visit_time = item.get("lastVisitTime").and_then(|v| v.as_str()).unwrap_or("Unknown");
                
                if !title.is_empty() {
                    layer.use_text(&format!("   Title: {}", title), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                    ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                }
                draw_wrapped_text(&layer, &format!("   URL: {}", url), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
                layer.use_text(&format!("   Last Visit: {}", visit_time), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                
                // Show flags if present
                if let Some(flags) = item.get("flags").and_then(|f| f.as_array()) {
                    if !flags.is_empty() {
                        layer.set_fill_color(color_critical());
                        let flags_str: Vec<String> = flags.iter()
                            .filter_map(|f| f.as_str().map(|s| s.to_string()))
                            .collect();
                        layer.use_text(&format!("   ⚠ FLAGS: {}", flags_str.join(", ")), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
                        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                        layer.set_fill_color(color_gray());
                    }
                }
            }
            "Download" => {
                let target = item.get("targetPath").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let end_time = item.get("endTime").and_then(|v| v.as_str()).unwrap_or("Unknown");
                
                draw_wrapped_text(&layer, &format!("   File: {}", target), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
                draw_wrapped_text(&layer, &format!("   From: {}", url), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
                layer.use_text(&format!("   Downloaded: {}", end_time), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                
                // Show flags if present
                if let Some(flags) = item.get("flags").and_then(|f| f.as_array()) {
                    if !flags.is_empty() {
                        layer.set_fill_color(color_critical());
                        let flags_str: Vec<String> = flags.iter()
                            .filter_map(|f| f.as_str().map(|s| s.to_string()))
                            .collect();
                        layer.use_text(&format!("   ⚠ FLAGS: {}", flags_str.join(", ")), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
                        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                        layer.set_fill_color(color_gray());
                    }
                }
            }
            "Credential" => {
                let origin = item.get("originUrl").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let username = item.get("username").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let created = item.get("dateCreated").and_then(|v| v.as_str()).unwrap_or("Unknown");
                
                layer.use_text(&format!("   Website: {}", origin), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                layer.use_text(&format!("   Username: {}", username), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                layer.use_text(&format!("   Created: {}", created), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
            }
            _ => {}
        }
        
        ctx.y_position -= Mm(LINE_HEIGHT_SECTION - LINE_HEIGHT_BODY);
        layer.set_fill_color(color_text());
    }
    
    ctx.y_position -= Mm(5.0);
    Ok(())
}

fn draw_flagged_intrusion(ctx: &mut PdfContext, intrusion: &serde_json::Map<String, serde_json::Value>, _payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    ctx.check_page_break(40.0);
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    
    // Main section header
    layer.set_fill_color(color_primary());
    layer.use_text("INTRUSION DETECTION RESULTS", FONT_SIZE_HEADING, left_margin, ctx.y_position, ctx.font_bold);
    ctx.y_position -= Mm(LINE_HEIGHT_SECTION);
    
    // Get summary if available
    if let Some(summary) = intrusion.get("summary").and_then(|s| s.as_object()) {
        ctx.check_page_break(25.0);
        let layer = ctx.current_layer();
        
        // Risk Score
        if let Some(risk_score) = summary.get("overallRiskScore").and_then(|v| v.as_u64()) {
            layer.set_fill_color(color_accent());
            layer.use_text(&format!("OVERALL RISK SCORE: {}/100", risk_score), FONT_SIZE_SUBHEADING, left_margin, ctx.y_position, ctx.font_bold);
            ctx.y_position -= Mm(LINE_HEIGHT_SECTION);
        }
        
        layer.set_fill_color(color_text());
        
        // Findings breakdown
        if let Some(total) = summary.get("totalArtifacts").and_then(|v| v.as_u64()) {
            layer.use_text(&format!("Total Artifacts Found: {}", total), FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font);
            ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        }
        
        if let Some(critical) = summary.get("criticalFindings").and_then(|v| v.as_u64()) {
            if critical > 0 {
                layer.set_fill_color(color_primary());
                layer.use_text(&format!("  CRITICAL Findings: {}", critical), FONT_SIZE_BODY, left_margin + Mm(5.0), ctx.y_position, ctx.font_bold);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
            }
        }
        
        layer.set_fill_color(color_text());
        
        if let Some(high) = summary.get("highRiskFindings").and_then(|v| v.as_u64()) {
            if high > 0 {
                layer.use_text(&format!("  HIGH Risk: {}", high), FONT_SIZE_BODY, left_margin + Mm(5.0), ctx.y_position, ctx.font);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
            }
        }
        
        if let Some(medium) = summary.get("mediumRiskFindings").and_then(|v| v.as_u64()) {
            if medium > 0 {
                layer.use_text(&format!("  MEDIUM Risk: {}", medium), FONT_SIZE_BODY, left_margin + Mm(5.0), ctx.y_position, ctx.font);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
            }
        }
        
        ctx.y_position -= Mm(LINE_HEIGHT_SECTION);
        
        // Recommendations
        if let Some(recommendations) = summary.get("recommendations").and_then(|v| v.as_array()) {
            if !recommendations.is_empty() {
                ctx.check_page_break(30.0);
                let layer = ctx.current_layer();
                
                layer.set_fill_color(color_accent());
                layer.use_text("RECOMMENDED ACTIONS:", FONT_SIZE_SUBHEADING, left_margin, ctx.y_position, ctx.font_bold);
                ctx.y_position -= Mm(LINE_HEIGHT_SECTION);
                
                layer.set_fill_color(color_text());
                
                for rec in recommendations.iter().take(10) {
                    if let Some(rec_text) = rec.as_str() {
                        ctx.check_page_break(8.0);
                        let layer = ctx.current_layer();
                        
                        // Wrap text if needed
                        let max_width = 170.0;
                        if rec_text.len() > 80 {
                            // Simple word wrap
                            let words: Vec<&str> = rec_text.split_whitespace().collect();
                            let mut line = String::from("  - ");
                            
                            for word in words {
                                if line.len() + word.len() > 80 {
                                    layer.use_text(&line, FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                                    ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                                    line = format!("    {}", word);
                                } else {
                                    line.push(' ');
                                    line.push_str(word);
                                }
                            }
                            if !line.trim().is_empty() {
                                layer.use_text(&line, FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                            }
                        } else {
                            layer.use_text(&format!("  - {}", rec_text), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                            ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                        }
                    }
                }
                
                ctx.y_position -= Mm(LINE_HEIGHT_SECTION);
            }
        }
    }
    
    // Security Tampering
    if let Some(tampering) = intrusion.get("securityToolTampering").and_then(|v| v.as_array()) {
        if !tampering.is_empty() {
            draw_intrusion_subsection(ctx, "SECURITY TOOL TAMPERING", tampering, |item| {
                format!("{}: {}",
                    item.get("component").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    item.get("details").and_then(|v| v.as_str()).unwrap_or("")
                )
            })?;
        }
    }
    
    // Remote Access Indicators
    if let Some(remote) = intrusion.get("remoteAccessIndicators").and_then(|v| v.as_array()) {
        if !remote.is_empty() {
            draw_intrusion_subsection(ctx, "REMOTE ACCESS INDICATORS", remote, |item| {
                format!("{} - {}",
                    item.get("toolName").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    item.get("details").and_then(|v| v.as_str()).unwrap_or("")
                )
            })?;
        }
    }
    
    // User Account Changes
    if let Some(accounts) = intrusion.get("userAccountChanges").and_then(|v| v.as_array()) {
        if !accounts.is_empty() {
            draw_intrusion_subsection(ctx, "USER ACCOUNT CHANGES", accounts, |item| {
                let username = item.get("username").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let is_admin = item.get("isAdmin").and_then(|v| v.as_bool()).unwrap_or(false);
                let admin_marker = if is_admin { " [ADMIN]" } else { "" };
                format!("{}{} - {}",
                    username,
                    admin_marker,
                    item.get("details").and_then(|v| v.as_str()).unwrap_or("")
                )
            })?;
        }
    }
    
    // Malware Indicators
    if let Some(malware) = intrusion.get("malwareIndicators").and_then(|v| v.as_array()) {
        if !malware.is_empty() {
            draw_intrusion_subsection(ctx, "MALWARE INDICATORS", malware, |item| {
                format!("{} - {}",
                    item.get("filePath").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    item.get("details").and_then(|v| v.as_str()).unwrap_or("")
                )
            })?;
        }
    }
    
    // Network Indicators
    if let Some(network) = intrusion.get("networkIndicators").and_then(|v| v.as_array()) {
        if !network.is_empty() {
            draw_intrusion_subsection(ctx, "NETWORK INDICATORS", network, |item| {
                format!("{} - {}",
                    item.get("destination").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    item.get("details").and_then(|v| v.as_str()).unwrap_or("")
                )
            })?;
        }
    }
    
    // Browser Hijacking
    if let Some(hijacking) = intrusion.get("browserHijacking").and_then(|v| v.as_array()) {
        if !hijacking.is_empty() {
            draw_intrusion_subsection(ctx, "BROWSER HIJACKING", hijacking, |item| {
                format!("{}: {}",
                    item.get("itemName").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    item.get("value").and_then(|v| v.as_str()).unwrap_or("")
                )
            })?;
        }
    }
    
    // Persistence Items (if flagged/suspicious)
    if let Some(persistence) = intrusion.get("persistenceItems").and_then(|v| v.as_array()) {
        let suspicious: Vec<serde_json::Value> = persistence.iter()
            .filter(|item| item.get("suspicious").and_then(|v| v.as_bool()).unwrap_or(false))
            .cloned()
            .collect();
        
        if !suspicious.is_empty() {
            draw_intrusion_subsection(ctx, "SUSPICIOUS PERSISTENCE ITEMS", &suspicious, |item| {
                format!("{}: {}",
                    item.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown"),
                    item.get("targetPath").and_then(|v| v.as_str()).unwrap_or("")
                )
            })?;
        }
    }
    
    ctx.y_position -= Mm(5.0);
    Ok(())
}

fn draw_intrusion_subsection<F>(
    ctx: &mut PdfContext,
    title: &str,
    items: &[serde_json::Value],
    format_fn: F,
) -> Result<(), Box<dyn Error>>
where
    F: Fn(&serde_json::Value) -> String,
{
    ctx.check_page_break(20.0);
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    
    // Subsection header
    layer.set_fill_color(color_accent());
    layer.use_text(&format!("{} ({})", title, items.len()), FONT_SIZE_SUBHEADING, left_margin, ctx.y_position, ctx.font_bold);
    ctx.y_position -= Mm(LINE_HEIGHT_SECTION);
    
    layer.set_fill_color(color_text());
    
    // List items (limit to first 20 to avoid huge PDFs)
    for (idx, item) in items.iter().take(20).enumerate() {
        ctx.check_page_break(8.0);
        let layer = ctx.current_layer();
        
        let text = format_fn(item);
        
        // Truncate if too long
        let display_text = if text.len() > 100 {
            format!("{}...", &text[..97])
        } else {
            text
        };
        
        layer.use_text(&format!("  {}. {}", idx + 1, display_text), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
    }
    
    if items.len() > 20 {
        let layer = ctx.current_layer();
        layer.set_fill_color(color_gray());
        layer.use_text(&format!("  ... and {} more items", items.len() - 20), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY);
    }
    
    ctx.y_position -= Mm(LINE_HEIGHT_SECTION);
    Ok(())
}

// Helper functions
fn draw_info_field(layer: &PdfLayerReference, label: &str, value: &str, x: Mm, mut y: Mm, font_bold: &IndirectFontRef, font: &IndirectFontRef) -> Mm {
    layer.set_fill_color(color_text());
    layer.use_text(label, FONT_SIZE_LABEL, x, y, font_bold);
    layer.use_text(&format!(" {}", value), FONT_SIZE_LABEL, x + Mm(45.0), y, font);
    y -= Mm(LINE_HEIGHT_BODY);
    y
}

/// Format a byte count into a human-readable string (KB/MB/GB).
fn format_bytes_human(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{} bytes", bytes)
    }
}

/// Deleted Media (Unallocated Space) triage section.
/// Renders one block per scanned drive: filesystem, estimate, named/header
/// counts, signature breakdown, recoverable file names, and the
/// detection-only disclaimer.
fn draw_deleted_media(ctx: &mut PdfContext, drives: &[serde_json::Value], _payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    ctx.check_page_break(40.0);
    let left_margin = Mm(PAGE_MARGIN);

    // Section header
    {
        let layer = ctx.current_layer();
        draw_left_border(&layer, left_margin, ctx.y_position, Mm(6.0), color_warning());
        layer.set_fill_color(color_primary());
        layer.use_text("DELETED MEDIA (UNALLOCATED SPACE)", FONT_SIZE_SUBHEADING, left_margin + Mm(5.0), ctx.y_position, ctx.font_bold);
        ctx.y_position -= Mm(8.0);

        layer.set_fill_color(color_gray());
        draw_wrapped_text(
            &layer,
            "Detection only. Scout reports whether deleted photos/videos remain physically present in unallocated space and estimates how many may be recoverable. It does not reconstruct or extract file data.",
            FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY,
        );
        ctx.y_position -= Mm(4.0);
    }

    for drive in drives {
        let drive_letter = drive.get("driveLetter").and_then(|v| v.as_str()).unwrap_or("?");
        let error = drive.get("error").and_then(|v| v.as_str()).filter(|s| !s.is_empty());
        let summary = drive.get("summary").filter(|s| !s.is_null());

        ctx.check_page_break(50.0);
        let layer = ctx.current_layer();

        // Per-drive sub-header
        layer.set_fill_color(color_primary());
        layer.use_text(&format!("Drive {}:", drive_letter.trim_end_matches(':')), FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font_bold);
        ctx.y_position -= Mm(LINE_HEIGHT_BODY + 1.0);

        // Error case
        if let Some(err) = error {
            layer.set_fill_color(color_critical());
            draw_wrapped_text(&layer, &format!("   Scan error: {}", err), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
            ctx.y_position -= Mm(3.0);
            continue;
        }

        let summary = match summary {
            Some(s) => s,
            None => {
                layer.set_fill_color(color_gray());
                layer.use_text("   No scan data for this drive.", FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY + 3.0);
                continue;
            }
        };

        let fs_type = summary.get("fsType").and_then(|v| v.as_str()).unwrap_or("Unknown");
        let found = summary.get("deletedMediaFound").and_then(|v| v.as_bool()).unwrap_or(false);
        let estimated = summary.get("estimatedTotal").and_then(|v| v.as_u64()).unwrap_or(0);
        let named_img = summary.get("namedImageCount").and_then(|v| v.as_u64()).unwrap_or(0);
        let named_vid = summary.get("namedVideoCount").and_then(|v| v.as_u64()).unwrap_or(0);
        let hdr_img = summary.get("unallocatedImageHeaders").and_then(|v| v.as_u64()).unwrap_or(0);
        let hdr_vid = summary.get("unallocatedVideoHeaders").and_then(|v| v.as_u64()).unwrap_or(0);
        let free_bytes = summary.get("freeBytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let scanned_bytes = summary.get("scannedBytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let cluster_size = summary.get("clusterSize").and_then(|v| v.as_u64()).unwrap_or(0);

        // Headline verdict
        if found {
            layer.set_fill_color(color_critical());
            layer.use_text(&format!("   Deleted media detected - ~{} file(s) potentially recoverable", estimated), FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font_bold);
        } else {
            layer.set_fill_color(color_success());
            layer.use_text("   No deleted media detected in unallocated space", FONT_SIZE_BODY, left_margin, ctx.y_position, ctx.font_bold);
        }
        ctx.y_position -= Mm(LINE_HEIGHT_BODY + 1.0);

        // Stat lines
        layer.set_fill_color(color_text());
        let stat_lines = [
            format!("   Filesystem: {}   -   Cluster size: {} bytes", fs_type, format_number(cluster_size)),
            format!("   Named deleted images: {}   -   Named deleted videos: {}", named_img, named_vid),
            format!("   Image headers in free space: {}   -   Video headers in free space: {}", hdr_img, hdr_vid),
            format!("   Free space: {}   -   Scanned: {}", format_bytes_human(free_bytes), format_bytes_human(scanned_bytes)),
        ];
        for line in &stat_lines {
            ctx.check_page_break(12.0);
            let layer = ctx.current_layer();
            layer.set_fill_color(color_text());
            layer.use_text(line, FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
            ctx.y_position -= Mm(LINE_HEIGHT_BODY);
        }

        // Signature breakdown
        if let Some(hits) = summary.get("headerHits").and_then(|v| v.as_array()) {
            if !hits.is_empty() {
                let parts: Vec<String> = hits.iter().map(|h| {
                    let sig = h.get("signature").and_then(|v| v.as_str()).unwrap_or("?");
                    let cnt = h.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                    format!("{} x{}", sig, cnt)
                }).collect();
                ctx.check_page_break(12.0);
                let layer = ctx.current_layer();
                layer.set_fill_color(color_gray());
                draw_wrapped_text(&layer, &format!("   Signatures in free space: {}", parts.join(", ")), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
            }
        }

        // Recoverable file names (metadata residue)
        if let Some(files) = summary.get("namedFiles").and_then(|v| v.as_array()) {
            if !files.is_empty() {
                ctx.check_page_break(14.0);
                let layer = ctx.current_layer();
                layer.set_fill_color(color_primary());
                layer.use_text(&format!("   Recoverable file names ({}):", files.len()), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);

                let cap = 40usize;
                for f in files.iter().take(cap) {
                    let name = f.get("fileName").and_then(|v| v.as_str()).unwrap_or("(unknown)");
                    let size = f.get("sizeBytes").and_then(|v| v.as_u64()).unwrap_or(0);
                    let mtype = f.get("mediaType").and_then(|v| v.as_str()).unwrap_or("");
                    let recov = f.get("likelyRecoverable").and_then(|v| v.as_bool()).unwrap_or(false);
                    ctx.check_page_break(10.0);
                    let layer = ctx.current_layer();
                    layer.set_fill_color(color_gray());
                    let mark = if recov { "recoverable" } else { "fragmented" };
                    draw_wrapped_text(
                        &layer,
                        &format!("      - {}  [{}, {}, {}]", name, mtype, format_bytes_human(size), mark),
                        FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY,
                    );
                }
                if files.len() > cap {
                    ctx.check_page_break(10.0);
                    let layer = ctx.current_layer();
                    layer.set_fill_color(color_gray());
                    layer.use_text(&format!("      ... and {} more", files.len() - cap), FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font);
                    ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                }
            }
        }

        // Interpretation notes from the engine
        if let Some(notes) = summary.get("notes").and_then(|v| v.as_array()) {
            if !notes.is_empty() {
                ctx.check_page_break(12.0);
                let layer = ctx.current_layer();
                layer.set_fill_color(color_gray());
                layer.use_text("   Notes:", FONT_SIZE_SMALL, left_margin, ctx.y_position, ctx.font_bold);
                ctx.y_position -= Mm(LINE_HEIGHT_BODY);
                for note in notes {
                    if let Some(n) = note.as_str() {
                        ctx.check_page_break(10.0);
                        let layer = ctx.current_layer();
                        layer.set_fill_color(color_gray());
                        draw_wrapped_text(&layer, &format!("      - {}", n), FONT_SIZE_SMALL, left_margin, &mut ctx.y_position, ctx.font, LINE_HEIGHT_BODY);
                    }
                }
            }
        }

        ctx.y_position -= Mm(LINE_HEIGHT_SECTION);
    }

    ctx.y_position -= Mm(3.0);
    Ok(())
}

/// Wrap long text into multiple lines that fit within the usable page width.
/// Uses an approximate character width for the given font size.
/// Returns the lines and the total vertical space consumed.
fn draw_wrapped_text(
    layer: &printpdf::PdfLayerReference,
    text: &str,
    font_size: f32,
    x: Mm,
    y: &mut Mm,
    font: &printpdf::IndirectFontRef,
    line_height: f32,
) {
    // Approximate characters per line at given font size
    // Usable width = PAGE_WIDTH - 2*PAGE_MARGIN = 170mm
    // At 9pt, ~2.2mm per char average ≈ 77 chars. At 11pt, ~2.6mm ≈ 65 chars.
    let usable_width_mm = PAGE_WIDTH - 2.0 * PAGE_MARGIN;
    let avg_char_width_mm = font_size * 0.24; // empirical ratio for Helvetica
    let max_chars = (usable_width_mm / avg_char_width_mm) as usize;
    
    if max_chars == 0 || text.len() <= max_chars {
        layer.use_text(text, font_size, x, *y, font);
        *y -= Mm(line_height);
        return;
    }
    
    // Split into lines, preferring to break at path separators or spaces
    let mut remaining = text;
    while !remaining.is_empty() {
        if remaining.len() <= max_chars {
            layer.use_text(remaining, font_size, x, *y, font);
            *y -= Mm(line_height);
            break;
        }
        
        // Find a good break point: look for backslash, forward slash, or space near the limit
        let chunk = &remaining[..max_chars];
        let break_at = chunk.rfind('\\')
            .or_else(|| chunk.rfind('/'))
            .or_else(|| chunk.rfind(' '))
            .map(|pos| pos + 1) // break after the separator
            .unwrap_or(max_chars); // hard break if no separator found
        
        layer.use_text(&remaining[..break_at], font_size, x, *y, font);
        *y -= Mm(line_height);
        remaining = &remaining[break_at..];
    }
}

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    let mut count = 0;
    
    for c in s.chars().rev() {
        if count == 3 {
            result.push(',');
            count = 0;
        }
        result.push(c);
        count += 1;
    }
    
    result.chars().rev().collect()
}

// ========== SYSTEM INFORMATION SECTION ==========
fn draw_system_info_section(ctx: &mut PdfContext, payload: &ReportPayload) -> Result<(), Box<dyn Error>> {
    let layer = ctx.current_layer();
    let left_margin = Mm(PAGE_MARGIN);
    let mut y = ctx.y_position;
    
    // Section header
    layer.set_fill_color(color_accent());
    layer.use_text("DEVICE INFORMATION", FONT_SIZE_HEADING, left_margin, y, ctx.font_bold);
    y -= Mm(LINE_HEIGHT_SECTION);
    
    // Check if we have system info data
    if payload.all_data.system_info.is_null() {
        layer.set_fill_color(color_gray());
        layer.use_text("No device information available", FONT_SIZE_BODY, left_margin, y, ctx.font);
        y -= Mm(LINE_HEIGHT_SECTION * 2.0);
        ctx.y_position = y;
        return Ok(());
    }
    
    layer.set_fill_color(color_text());
    
    // Computer Name
    if let Some(computer_name) = payload.all_data.system_info.get("computer_name").and_then(|v| v.as_str()) {
        y = draw_info_field(&layer, "Computer Name:", computer_name, left_margin, y, ctx.font_bold, ctx.font);
    }
    
    // OS Version
    if let Some(os_version) = payload.all_data.system_info.get("os_version").and_then(|v| v.as_str()) {
        y = draw_info_field(&layer, "Operating System:", os_version, left_margin, y, ctx.font_bold, ctx.font);
    }
    
    // Registered Owner
    if let Some(owner) = payload.all_data.system_info.get("registered_owner").and_then(|v| v.as_str()) {
        if !owner.is_empty() && owner != "null" {
            y = draw_info_field(&layer, "Registered Owner:", owner, left_margin, y, ctx.font_bold, ctx.font);
        }
    }
    
    // Registered Organization
    if let Some(org) = payload.all_data.system_info.get("registered_organization").and_then(|v| v.as_str()) {
        if !org.is_empty() && org != "null" {
            y = draw_info_field(&layer, "Organization:", org, left_margin, y, ctx.font_bold, ctx.font);
        }
    }
    
    // Product ID
    if let Some(product_id) = payload.all_data.system_info.get("product_id").and_then(|v| v.as_str()) {
        if !product_id.is_empty() && product_id != "null" {
            y = draw_info_field(&layer, "Product ID:", product_id, left_margin, y, ctx.font_bold, ctx.font);
        }
    }
    
    // Domain
    if let Some(domain) = payload.all_data.system_info.get("domain").and_then(|v| v.as_str()) {
        if !domain.is_empty() && domain != "null" {
            y = draw_info_field(&layer, "Domain:", domain, left_margin, y, ctx.font_bold, ctx.font);
        }
    }
    
    y -= Mm(5.0);
    
    // User Accounts
    if let Some(accounts) = payload.all_data.system_info.get("user_accounts").and_then(|v| v.as_array()) {
        if !accounts.is_empty() {
            ctx.check_page_break(30.0);
            let layer = ctx.current_layer();
            
            layer.set_fill_color(color_accent());
            layer.use_text("User Accounts:", FONT_SIZE_SUBHEADING, left_margin, y, ctx.font_bold);
            y -= Mm(LINE_HEIGHT_SECTION);
            
            layer.set_fill_color(color_text());
            for account in accounts {
                ctx.check_page_break(15.0);
                let layer = ctx.current_layer();
                
                if let Some(username) = account.get("username").and_then(|v| v.as_str()) {
                    layer.use_text(&format!("• {}", username), FONT_SIZE_BODY, left_margin + Mm(5.0), y, ctx.font);
                    y -= Mm(LINE_HEIGHT_BODY);
                    
                    if let Some(full_name) = account.get("full_name").and_then(|v| v.as_str()) {
                        if !full_name.is_empty() && full_name != "null" {
                            layer.set_fill_color(color_gray());
                            layer.use_text(&format!("  Name: {}", full_name), FONT_SIZE_SMALL, left_margin + Mm(10.0), y, ctx.font);
                            y -= Mm(LINE_HEIGHT_BODY);
                            layer.set_fill_color(color_text());
                        }
                    }
                    
                    if let Some(account_type) = account.get("account_type").and_then(|v| v.as_str()) {
                        layer.set_fill_color(color_gray());
                        layer.use_text(&format!("  Type: {}", account_type), FONT_SIZE_SMALL, left_margin + Mm(10.0), y, ctx.font);
                        y -= Mm(LINE_HEIGHT_BODY);
                        layer.set_fill_color(color_text());
                    }
                    
                    y -= Mm(2.0);
                }
            }
        }
    }
    
    y -= Mm(5.0);
    
    // Hardware Information
    if let Some(hardware) = payload.all_data.system_info.get("hardware") {
        ctx.check_page_break(30.0);
        let layer = ctx.current_layer();
        
        layer.set_fill_color(color_accent());
        layer.use_text("Hardware Information:", FONT_SIZE_SUBHEADING, left_margin, y, ctx.font_bold);
        y -= Mm(LINE_HEIGHT_SECTION);
        
        layer.set_fill_color(color_text());
        
        if let Some(mb_serial) = hardware.get("motherboard_serial").and_then(|v| v.as_str()) {
            if !mb_serial.is_empty() && mb_serial != "null" {
                y = draw_info_field(&layer, "Motherboard Serial:", mb_serial, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
            }
        }
        
        if let Some(bios_serial) = hardware.get("bios_serial").and_then(|v| v.as_str()) {
            if !bios_serial.is_empty() && bios_serial != "null" {
                y = draw_info_field(&layer, "BIOS Serial:", bios_serial, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
            }
        }
        
        if let Some(uuid) = hardware.get("system_uuid").and_then(|v| v.as_str()) {
            if !uuid.is_empty() && uuid != "null" {
                y = draw_info_field(&layer, "System UUID:", uuid, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
            }
        }
        
        // Drives
        if let Some(drives) = hardware.get("drives").and_then(|v| v.as_array()) {
            if !drives.is_empty() {
                y -= Mm(3.0);
                ctx.check_page_break(20.0);
                let layer = ctx.current_layer();
                
                layer.use_text("Storage Drives:", FONT_SIZE_LABEL, left_margin + Mm(5.0), y, ctx.font_bold);
                y -= Mm(LINE_HEIGHT_BODY);
                
                for drive in drives {
                    ctx.check_page_break(12.0);
                    let layer = ctx.current_layer();
                    
                    if let Some(letter) = drive.get("letter").and_then(|v| v.as_str()) {
                        let label = drive.get("label").and_then(|v| v.as_str()).unwrap_or("");
                        let serial = drive.get("serial_number").and_then(|v| v.as_str()).unwrap_or("Unknown");
                        
                        let drive_info = if !label.is_empty() {
                            format!("{} ({}) - S/N: {}", letter, label, serial)
                        } else {
                            format!("{} - S/N: {}", letter, serial)
                        };
                        
                        layer.use_text(&format!("  • {}", drive_info), FONT_SIZE_SMALL, left_margin + Mm(10.0), y, ctx.font);
                        y -= Mm(LINE_HEIGHT_BODY);
                    }
                }
            }
        }
    }
    
    y -= Mm(5.0);
    
    // Network Information
    if let Some(network) = payload.all_data.system_info.get("network") {
        ctx.check_page_break(25.0);
        let layer = ctx.current_layer();
        
        layer.set_fill_color(color_accent());
        layer.use_text("Network Information:", FONT_SIZE_SUBHEADING, left_margin, y, ctx.font_bold);
        y -= Mm(LINE_HEIGHT_SECTION);
        
        layer.set_fill_color(color_text());
        
        if let Some(hostname) = network.get("hostname").and_then(|v| v.as_str()) {
            y = draw_info_field(&layer, "Hostname:", hostname, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
        }
        
        if let Some(macs) = network.get("mac_addresses").and_then(|v| v.as_array()) {
            if !macs.is_empty() {
                layer.use_text("MAC Addresses:", FONT_SIZE_LABEL, left_margin + Mm(5.0), y, ctx.font_bold);
                y -= Mm(LINE_HEIGHT_BODY);
                
                for mac in macs {
                    if let Some(mac_str) = mac.as_str() {
                        ctx.check_page_break(5.0);
                        let layer = ctx.current_layer();
                        layer.use_text(&format!("  • {}", mac_str), FONT_SIZE_SMALL, left_margin + Mm(10.0), y, ctx.font);
                        y -= Mm(LINE_HEIGHT_BODY);
                    }
                }
            }
        }
        
        if let Some(ips) = network.get("ip_addresses").and_then(|v| v.as_array()) {
            if !ips.is_empty() {
                layer.use_text("IP Addresses:", FONT_SIZE_LABEL, left_margin + Mm(5.0), y, ctx.font_bold);
                y -= Mm(LINE_HEIGHT_BODY);
                
                for ip in ips {
                    if let Some(ip_str) = ip.as_str() {
                        ctx.check_page_break(5.0);
                        let layer = ctx.current_layer();
                        layer.use_text(&format!("  • {}", ip_str), FONT_SIZE_SMALL, left_margin + Mm(10.0), y, ctx.font);
                        y -= Mm(LINE_HEIGHT_BODY);
                    }
                }
            }
        }
        
        // Public IP Address
        if let Some(public_ip) = network.get("public_ip").and_then(|v| v.as_str()) {
            if !public_ip.is_empty() && public_ip != "null" {
                ctx.check_page_break(7.0);
                let layer = ctx.current_layer();
                y = draw_info_field(&layer, "Public IP Address:", public_ip, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
            }
        }
    }
    
    // Discovered Email Addresses
    if let Some(emails) = payload.all_data.system_info.get("emails").and_then(|v| v.as_array()) {
        if !emails.is_empty() {
            y -= Mm(5.0);
            ctx.check_page_break(20.0);
            let layer = ctx.current_layer();
            
            layer.set_fill_color(color_accent());
            layer.use_text("Discovered Email Addresses:", FONT_SIZE_SUBHEADING, left_margin, y, ctx.font_bold);
            y -= Mm(LINE_HEIGHT_SECTION);
            
            layer.set_fill_color(color_text());
            for email in emails {
                if let Some(email_str) = email.as_str() {
                    ctx.check_page_break(5.0);
                    let layer = ctx.current_layer();
                    layer.use_text(&format!("• {}", email_str), FONT_SIZE_BODY, left_margin + Mm(5.0), y, ctx.font);
                    y -= Mm(LINE_HEIGHT_BODY);
                }
            }
        }
    }
    
    // USB Device Information (for USB scans)
    if let Some(usb_info) = payload.all_data.system_info.get("usb_device_info") {
        y -= Mm(5.0);
        ctx.check_page_break(30.0);
        let layer = ctx.current_layer();
        
        layer.set_fill_color(color_accent());
        layer.use_text("USB Device Information:", FONT_SIZE_SUBHEADING, left_margin, y, ctx.font_bold);
        y -= Mm(LINE_HEIGHT_SECTION);
        
        layer.set_fill_color(color_text());
        
        if let Some(drive_name) = usb_info.get("drive_name").and_then(|v| v.as_str()) {
            y = draw_info_field(&layer, "Drive Name:", drive_name, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
        }
        
        if let Some(drive_letter) = usb_info.get("drive_letter").and_then(|v| v.as_str()) {
            y = draw_info_field(&layer, "Drive Letter:", drive_letter, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
        }
        
        if let Some(make) = usb_info.get("make").and_then(|v| v.as_str()) {
            if !make.is_empty() {
                y = draw_info_field(&layer, "Manufacturer:", make, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
            }
        }
        
        if let Some(model) = usb_info.get("model").and_then(|v| v.as_str()) {
            if !model.is_empty() {
                y = draw_info_field(&layer, "Model:", model, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
            }
        }
        
        if let Some(capacity) = usb_info.get("capacity_gb").and_then(|v| v.as_f64()) {
            y = draw_info_field(&layer, "Total Capacity:", &format!("{:.2} GB", capacity), left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
        }
        
        if let Some(free_space) = usb_info.get("free_space_gb").and_then(|v| v.as_f64()) {
            y = draw_info_field(&layer, "Free Space:", &format!("{:.2} GB", free_space), left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
        }
        
        if let Some(used_space) = usb_info.get("used_space_gb").and_then(|v| v.as_f64()) {
            y = draw_info_field(&layer, "Used Space:", &format!("{:.2} GB", used_space), left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
        }
        
        if let Some(serial) = usb_info.get("serial_number").and_then(|v| v.as_str()) {
            y = draw_info_field(&layer, "Serial Number:", serial, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
        }
        
        if let Some(volume_id) = usb_info.get("volume_id").and_then(|v| v.as_str()) {
            y = draw_info_field(&layer, "Volume ID:", volume_id, left_margin + Mm(5.0), y, ctx.font_bold, ctx.font);
        }
    }
    
    // USB Device History
    if let Some(usb_history) = payload.all_data.system_info.get("usb_history").and_then(|v| v.as_array()) {
        if !usb_history.is_empty() {
            y -= Mm(5.0);
            ctx.check_page_break(30.0);
            let layer = ctx.current_layer();
            
            layer.set_fill_color(color_accent());
            layer.use_text(&format!("USB Device History ({} devices):", usb_history.len()), FONT_SIZE_SUBHEADING, left_margin, y, ctx.font_bold);
            y -= Mm(LINE_HEIGHT_SECTION);
            
            layer.set_fill_color(color_text());
            
            for (idx, device) in usb_history.iter().take(20).enumerate() {
                ctx.check_page_break(20.0);
                let layer = ctx.current_layer();
                
                let device_name = device.get("device_name").and_then(|v| v.as_str()).unwrap_or("Unknown Device");
                layer.set_fill_color(color_text());
                layer.use_text(&format!("{}. {}", idx + 1, device_name), FONT_SIZE_BODY, left_margin + Mm(5.0), y, ctx.font_bold);
                y -= Mm(LINE_HEIGHT_BODY);
                
                if let Some(serial) = device.get("serial_number").and_then(|v| v.as_str()) {
                    if !serial.is_empty() {
                        ctx.check_page_break(5.0);
                        let layer = ctx.current_layer();
                        layer.set_fill_color(color_text());
                        layer.use_text(&format!("   Serial: {}", serial), FONT_SIZE_SMALL, left_margin + Mm(10.0), y, ctx.font);
                        y -= Mm(LINE_HEIGHT_BODY);
                    }
                }
                
                if let Some(last_connected) = device.get("last_connected").and_then(|v| v.as_str()) {
                    if !last_connected.is_empty() {
                        ctx.check_page_break(5.0);
                        let layer = ctx.current_layer();
                        layer.set_fill_color(color_gray());
                        layer.use_text(&format!("   Last Connected: {}", last_connected), FONT_SIZE_SMALL, left_margin + Mm(10.0), y, ctx.font);
                        y -= Mm(LINE_HEIGHT_BODY);
                    }
                }
                
                y -= Mm(2.0);
            }
            
            if usb_history.len() > 20 {
                ctx.check_page_break(5.0);
                let layer = ctx.current_layer();
                layer.set_fill_color(color_gray());
                layer.use_text(&format!("... and {} more devices", usb_history.len() - 20), FONT_SIZE_SMALL, left_margin + Mm(5.0), y, ctx.font);
                y -= Mm(LINE_HEIGHT_BODY);
            }
        }
    }
    
    y -= Mm(LINE_HEIGHT_SECTION * 2.0);
    ctx.y_position = y;
    
    Ok(())
}

pub fn generate_pdf(payload: &ReportPayload, reports_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let filename = generate_report_filename(&payload.metadata.case_number, "pdf");
    let filepath = reports_dir.join(&filename);
    
    eprintln!("Generating PDF report: {}", filepath.display());
    
    // Create PDF document
    let (doc, page_index, layer_index) = PdfDocument::new(
        "Project Hindsight - Digital Triage Report",
        Mm(PAGE_WIDTH),
        Mm(PAGE_HEIGHT),
        "Content",
    );
    
    // Load fonts
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    
    // Context for pagination
    let mut ctx = PdfContext {
        doc: &doc,
        page_index,
        layer_index,
        y_position: Mm(PAGE_HEIGHT - PAGE_MARGIN),
        font: &font,
        font_bold: &font_bold,
    };
    
    // ========== FACE PAGE ==========
    draw_face_page(&mut ctx, payload)?;
    
    // Start new page for detailed findings
    add_new_page(&mut ctx);
    
    // ========== DEVICE INFORMATION (ALWAYS INCLUDED) ==========
    draw_system_info_section(&mut ctx, payload)?;
    
    // ========== FLAGGED EVIDENCE BREAKDOWN ==========
    draw_flagged_evidence_sections(&mut ctx, payload)?;
    
    // Save PDF
    doc.save(&mut BufWriter::new(File::create(&filepath)?))?;
    eprintln!("✓ PDF report generated: {}", filepath.display());
    
    Ok(filepath)
}
