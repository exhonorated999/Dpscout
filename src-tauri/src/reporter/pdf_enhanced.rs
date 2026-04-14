// Enhanced PDF Report Generation with Professional Layout

use super::{ReportPayload, ReportScope, generate_report_filename};
use printpdf::*;
use std::error::Error;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

// Page dimensions (A4)
const PAGE_WIDTH: Mm = Mm(210.0);
const PAGE_HEIGHT: Mm = Mm(297.0);
const MARGIN_LEFT: Mm = Mm(20.0);
const MARGIN_RIGHT: Mm = Mm(190.0);
const MARGIN_TOP: Mm = Mm(277.0);
const MARGIN_BOTTOM: Mm = Mm(20.0);

// Font sizes
const FONT_SIZE_LOGO: f32 = 28.0;
const FONT_SIZE_TITLE: f32 = 20.0;
const FONT_SIZE_HEADING: f32 = 16.0;
const FONT_SIZE_SUBHEADING: f32 = 14.0;
const FONT_SIZE_BODY: f32 = 10.0;
const FONT_SIZE_SMALL: f32 = 8.0;

// Colors
fn color_red() -> Color {
    // Professional blue: #4169e1 -> RGB(65, 105, 225) -> (0.255, 0.412, 0.882)
    Color::Rgb(Rgb::new(0.255, 0.412, 0.882, None))
}

fn color_text() -> Color {
    Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None))
}

fn color_gray() -> Color {
    Color::Rgb(Rgb::new(0.4, 0.4, 0.4, None))
}

fn color_light_gray() -> Color {
    Color::Rgb(Rgb::new(0.8, 0.8, 0.8, None))
}

pub fn generate_pdf(payload: &ReportPayload, reports_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let filename = generate_report_filename(&payload.metadata.case_number, "pdf");
    let filepath = reports_dir.join(&filename);
    
    // Create PDF document
    let (mut doc, page1_idx, layer1_idx) = PdfDocument::new(
        "Project Hindsight - Digital Triage Report",
        PAGE_WIDTH,
        PAGE_HEIGHT,
        "Page 1",
    );
    
    // Use built-in fonts
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    
    // ========== PAGE 1: HEADER & SUMMARY ==========
    let current_layer = doc.get_page(page1_idx).get_layer(layer1_idx);
    let mut y_pos = MARGIN_TOP;
    
    // Header: Hindsight Logo & Title
    current_layer.set_fill_color(color_red());
    current_layer.use_text(
        "HINDSIGHT",
        FONT_SIZE_LOGO,
        MARGIN_LEFT,
        y_pos,
        &font_bold,
    );
    y_pos -= Mm(10.0);
    
    current_layer.set_fill_color(color_gray());
    current_layer.use_text(
        "Digital Forensic Triage Platform",
        FONT_SIZE_SMALL,
        MARGIN_LEFT,
        y_pos,
        &font,
    );
    y_pos -= Mm(15.0);
    
    // Draw horizontal line
    draw_horizontal_line(&current_layer, y_pos);
    y_pos -= Mm(10.0);
    
    // Officer & Agency Information
    if let Some(ref officer) = payload.metadata.officer_name {
        current_layer.set_fill_color(color_text());
        current_layer.use_text(
            &format!("Officer: {}", officer),
            FONT_SIZE_BODY,
            MARGIN_LEFT,
            y_pos,
            &font_bold,
        );
        y_pos -= Mm(5.0);
    }
    
    if let Some(ref agency) = payload.metadata.agency_name {
        current_layer.set_fill_color(color_text());
        current_layer.use_text(
            &format!("Agency: {}", agency),
            FONT_SIZE_BODY,
            MARGIN_LEFT,
            y_pos,
            &font,
        );
        y_pos -= Mm(10.0);
    }
    
    // Report Title
    current_layer.set_fill_color(color_text());
    current_layer.use_text(
        "DIGITAL TRIAGE REPORT",
        FONT_SIZE_TITLE,
        MARGIN_LEFT,
        y_pos,
        &font_bold,
    );
    y_pos -= Mm(12.0);
    
    // Case Information
    draw_section_header(&current_layer, "CASE INFORMATION", MARGIN_LEFT, &mut y_pos, &font_bold);
    draw_field_pair(&current_layer, "Case Number:", &payload.metadata.case_number, MARGIN_LEFT, &mut y_pos, &font_bold, &font);
    draw_field_pair(&current_layer, "Detective:", &payload.metadata.assigned_detective, MARGIN_LEFT, &mut y_pos, &font_bold, &font);
    draw_field_pair(&current_layer, "Report Generated:", &payload.metadata.generated_date, MARGIN_LEFT, &mut y_pos, &font_bold, &font);
    
    if let Some(ref device) = payload.metadata.device_name {
        draw_field_pair(&current_layer, "Device Name:", device, MARGIN_LEFT, &mut y_pos, &font_bold, &font);
    }
    
    if let Some(ref os) = payload.metadata.operating_system {
        draw_field_pair(&current_layer, "Operating System:", os, MARGIN_LEFT, &mut y_pos, &font_bold, &font);
    }
    
    y_pos -= Mm(5.0);
    
    // Scan Summary
    draw_section_header(&current_layer, "SCAN SUMMARY", MARGIN_LEFT, &mut y_pos, &font_bold);
    
    if let Some(ref drive) = payload.metadata.drive_scanned {
        draw_field_pair(&current_layer, "Drive Scanned:", drive, MARGIN_LEFT, &mut y_pos, &font_bold, &font);
    }
    
    if let Some(ref duration) = payload.metadata.scan_duration {
        draw_field_pair(&current_layer, "Scan Duration:", duration, MARGIN_LEFT, &mut y_pos, &font_bold, &font);
    }
    
    if let Some(flags) = payload.metadata.total_flags {
        current_layer.set_fill_color(color_red());
        draw_field_pair(&current_layer, "Total Flags:", &format!("{} items", flags), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        current_layer.set_fill_color(color_text());
    }
    
    y_pos -= Mm(3.0);
    
    // Scan Parameters
    if let Some(ref params) = payload.metadata.scan_parameters {
        draw_field_pair(&current_layer, "Scan Parameters:", "", MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        y_pos += Mm(5.0); // Adjust back since we'll list items
        
        if params.applications_scanned {
            draw_bullet_item(&current_layer, "Applications Scanned", MARGIN_LEFT + Mm(5.0), &mut y_pos, &font);
        }
        if params.browser_history_scanned {
            draw_bullet_item(&current_layer, "Browser History Analyzed", MARGIN_LEFT + Mm(5.0), &mut y_pos, &font);
        }
        if params.keyword_search_performed {
            draw_bullet_item(&current_layer, "Keyword Search Performed", MARGIN_LEFT + Mm(5.0), &mut y_pos, &font);
        }
        if params.hash_matching_performed {
            draw_bullet_item(&current_layer, "Hash Matching (CSAM Detection)", MARGIN_LEFT + Mm(5.0), &mut y_pos, &font);
        }
        if params.media_scan_performed {
            draw_bullet_item(&current_layer, "Media Files Scanned", MARGIN_LEFT + Mm(5.0), &mut y_pos, &font);
        }
        if params.intrusion_detection_performed {
            draw_bullet_item(&current_layer, "Intrusion Detection (WIN-ID)", MARGIN_LEFT + Mm(5.0), &mut y_pos, &font);
        }
    }
    
    y_pos -= Mm(10.0);
    
    // ========== PAGE 2+: RESULTS BREAKDOWN ==========
    // Add new page for results
    let (page2_idx, layer2_idx) = doc.add_page(PAGE_WIDTH, PAGE_HEIGHT, "Page 2");
    let current_layer = doc.get_page(page2_idx).get_layer(layer2_idx);
    let mut y_pos = MARGIN_TOP;
    
    // Page header
    draw_page_header(&current_layer, "RESULTS BREAKDOWN", 2, &font_bold, &font);
    y_pos -= Mm(15.0);
    
    // Questionable Applications
    if let Some(apps_array) = payload.all_data.apps.as_array() {
        let total_apps = apps_array.len();
        let flagged_apps: Vec<_> = apps_array.iter()
            .enumerate()
            .filter(|(idx, _)| {
                let app_prefix = format!("app-");
                let idx_suffix = format!("-{}", idx);
                payload.flagged_item_ids.iter().any(|id| id.contains(&app_prefix) && id.contains(&idx_suffix))
            })
            .collect();
        
        draw_section_header(&current_layer, "QUESTIONABLE APPLICATIONS", MARGIN_LEFT, &mut y_pos, &font_bold);
        draw_field_pair(&current_layer, "Total Applications Located:", &total_apps.to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        
        current_layer.set_fill_color(color_red());
        draw_field_pair(&current_layer, "Flagged Applications:", &flagged_apps.len().to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        current_layer.set_fill_color(color_text());
        
        y_pos -= Mm(3.0);
        
        if !flagged_apps.is_empty() {
            current_layer.use_text(
                "Flagged Application List:",
                FONT_SIZE_BODY,
                MARGIN_LEFT,
                y_pos,
                &font_bold,
            );
            y_pos -= Mm(5.0);
            
            for (idx, app) in flagged_apps.iter().take(20) { // Limit to 20 per page
                if y_pos < MARGIN_BOTTOM + Mm(20.0) {
                    // Add new page if needed
                    let (new_page_idx, new_layer_idx) = doc.add_page(PAGE_WIDTH, PAGE_HEIGHT, "Page");
                    let current_layer = doc.get_page(new_page_idx).get_layer(new_layer_idx);
                    y_pos = MARGIN_TOP;
                    draw_page_header(&current_layer, "RESULTS BREAKDOWN (cont.)", 0, &font_bold, &font);
                    y_pos -= Mm(15.0);
                }
                
                if let Some(name) = app.get("name").and_then(|n| n.as_str()) {
                    let category = app.get("category").and_then(|c| c.as_str()).unwrap_or("Unknown");
                    draw_bullet_item(&current_layer, &format!("{} ({})", name, category), MARGIN_LEFT + Mm(3.0), &mut y_pos, &font);
                }
            }
        }
        
        y_pos -= Mm(8.0);
    }
    
    // Browser History
    if let Some(browsers_array) = payload.all_data.browsers.as_array() {
        let total_entries: usize = browsers_array.iter()
            .filter_map(|b| b.get("history").and_then(|h| h.as_array()))
            .map(|h| h.len())
            .sum();
        
        let empty_vec = vec![];
        let flagged_entries: Vec<_> = browsers_array.iter()
            .flat_map(|b| b.get("history").and_then(|h| h.as_array()).unwrap_or(&empty_vec).iter())
            .enumerate()
            .filter(|(idx, _)| {
                let idx_suffix = format!("-{}", idx);
                payload.flagged_item_ids.iter().any(|id| id.contains("browser-") && id.contains(&idx_suffix))
            })
            .collect();
        
        draw_section_header(&current_layer, "BROWSER HISTORY", MARGIN_LEFT, &mut y_pos, &font_bold);
        draw_field_pair(&current_layer, "Browsers Located:", &browsers_array.len().to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        draw_field_pair(&current_layer, "Total History Entries:", &total_entries.to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        
        current_layer.set_fill_color(color_red());
        draw_field_pair(&current_layer, "Flagged Entries:", &flagged_entries.len().to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        current_layer.set_fill_color(color_text());
        
        y_pos -= Mm(3.0);
        
        if !flagged_entries.is_empty() {
            current_layer.use_text(
                "Flagged History Entries:",
                FONT_SIZE_BODY,
                MARGIN_LEFT,
                y_pos,
                &font_bold,
            );
            y_pos -= Mm(5.0);
            
            for (idx, entry) in flagged_entries.iter().take(20) {
                if y_pos < MARGIN_BOTTOM + Mm(20.0) {
                    let (new_page_idx, new_layer_idx) = doc.add_page(PAGE_WIDTH, PAGE_HEIGHT, "Page");
                    let current_layer = doc.get_page(new_page_idx).get_layer(new_layer_idx);
                    y_pos = MARGIN_TOP;
                    draw_page_header(&current_layer, "RESULTS BREAKDOWN (cont.)", 0, &font_bold, &font);
                    y_pos -= Mm(15.0);
                }
                
                if let Some(url) = entry.get("url").and_then(|u| u.as_str()) {
                    let title = entry.get("title").and_then(|t| t.as_str()).unwrap_or("No title");
                    draw_bullet_item(&current_layer, &format!("{} - {}", title, url), MARGIN_LEFT + Mm(3.0), &mut y_pos, &font);
                }
            }
        }
        
        y_pos -= Mm(8.0);
    }
    
    // Keyword Hits
    if let Some(keywords_array) = payload.all_data.keywords.as_array() {
        let total_keywords = keywords_array.len();
        let flagged_keywords: Vec<_> = keywords_array.iter()
            .enumerate()
            .filter(|(idx, _)| {
                let idx_suffix = format!("-{}", idx);
                payload.flagged_item_ids.iter().any(|id| id.contains("keyword-") && id.contains(&idx_suffix))
            })
            .collect();
        
        draw_section_header(&current_layer, "KEYWORD HITS", MARGIN_LEFT, &mut y_pos, &font_bold);
        draw_field_pair(&current_layer, "Total Files with Keywords:", &total_keywords.to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        
        current_layer.set_fill_color(color_red());
        draw_field_pair(&current_layer, "Flagged Keyword Matches:", &flagged_keywords.len().to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        current_layer.set_fill_color(color_text());
        
        y_pos -= Mm(3.0);
        
        if !flagged_keywords.is_empty() {
            current_layer.use_text(
                "Flagged Files:",
                FONT_SIZE_BODY,
                MARGIN_LEFT,
                y_pos,
                &font_bold,
            );
            y_pos -= Mm(5.0);
            
            for (idx, kw) in flagged_keywords.iter().take(20) {
                if y_pos < MARGIN_BOTTOM + Mm(20.0) {
                    let (new_page_idx, new_layer_idx) = doc.add_page(PAGE_WIDTH, PAGE_HEIGHT, "Page");
                    let current_layer = doc.get_page(new_page_idx).get_layer(new_layer_idx);
                    y_pos = MARGIN_TOP;
                    draw_page_header(&current_layer, "RESULTS BREAKDOWN (cont.)", 0, &font_bold, &font);
                    y_pos -= Mm(15.0);
                }
                
                if let Some(path) = kw.get("filePath").and_then(|p| p.as_str()) {
                    let keywords_str = kw.get("matchedKeywords")
                        .and_then(|k| k.as_array())
                        .map(|arr| arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", "))
                        .unwrap_or_else(|| "Unknown".to_string());
                    
                    draw_bullet_item(&current_layer, &format!("{} [{}]", path, keywords_str), MARGIN_LEFT + Mm(3.0), &mut y_pos, &font);
                }
            }
        }
        
        y_pos -= Mm(8.0);
    }
    
    // Hash Hits (CSAM)
    if let Some(csam_array) = payload.all_data.csam.as_array() {
        let total_hashes = csam_array.len();
        let flagged_hashes: Vec<_> = csam_array.iter()
            .enumerate()
            .filter(|(idx, _)| {
                let idx_suffix = format!("-{}", idx);
                payload.flagged_item_ids.iter().any(|id| id.contains("media-") && id.contains(&idx_suffix))
            })
            .collect();
        
        draw_section_header(&current_layer, "HASH HITS (CSAM DETECTION)", MARGIN_LEFT, &mut y_pos, &font_bold);
        draw_field_pair(&current_layer, "Total Media Files Scanned:", &total_hashes.to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        
        current_layer.set_fill_color(color_red());
        draw_field_pair(&current_layer, "CRITICAL - Hash Matches:", &flagged_hashes.len().to_string(), MARGIN_LEFT, &mut y_pos, &font_bold, &font);
        current_layer.set_fill_color(color_text());
        
        y_pos -= Mm(3.0);
        
        if !flagged_hashes.is_empty() {
            current_layer.set_fill_color(color_red());
            current_layer.use_text(
                "⚠ CRITICAL: Flagged Files (CSAM):",
                FONT_SIZE_BODY,
                MARGIN_LEFT,
                y_pos,
                &font_bold,
            );
            current_layer.set_fill_color(color_text());
            y_pos -= Mm(5.0);
            
            for (idx, hash_match) in flagged_hashes.iter().take(20) {
                if y_pos < MARGIN_BOTTOM + Mm(20.0) {
                    let (new_page_idx, new_layer_idx) = doc.add_page(PAGE_WIDTH, PAGE_HEIGHT, "Page");
                    let current_layer = doc.get_page(new_page_idx).get_layer(new_layer_idx);
                    y_pos = MARGIN_TOP;
                    draw_page_header(&current_layer, "RESULTS BREAKDOWN (cont.)", 0, &font_bold, &font);
                    y_pos -= Mm(15.0);
                }
                
                if let Some(path) = hash_match.get("filePath").and_then(|p| p.as_str()) {
                    let hash = hash_match.get("md5Hash")
                        .or_else(|| hash_match.get("sha256Hash"))
                        .and_then(|h| h.as_str())
                        .unwrap_or("Unknown");
                    
                    draw_bullet_item(&current_layer, &format!("{}", path), MARGIN_LEFT + Mm(3.0), &mut y_pos, &font);
                    draw_bullet_item(&current_layer, &format!("  Hash: {}", &hash[..16.min(hash.len())]), MARGIN_LEFT + Mm(6.0), &mut y_pos, &font);
                }
            }
        }
    }
    
    // Save PDF
    doc.save(&mut BufWriter::new(File::create(&filepath)?))?;
    
    Ok(filepath)
}

// Helper functions

fn draw_horizontal_line(_layer: &PdfLayerReference, _y: Mm) {
    // TODO: Fix line drawing with correct printpdf API
    // Temporarily disabled to allow compilation
}

fn draw_section_header(layer: &PdfLayerReference, text: &str, x: Mm, y: &mut Mm, font: &IndirectFontRef) {
    layer.set_fill_color(color_red());
    layer.use_text(text, FONT_SIZE_HEADING, x, *y, font);
    *y -= Mm(7.0);
    layer.set_fill_color(color_text());
}

fn draw_field_pair(layer: &PdfLayerReference, label: &str, value: &str, x: Mm, y: &mut Mm, font_bold: &IndirectFontRef, font: &IndirectFontRef) {
    layer.set_fill_color(color_text());
    layer.use_text(label, FONT_SIZE_BODY, x, *y, font_bold);
    layer.use_text(value, FONT_SIZE_BODY, x + Mm(50.0), *y, font);
    *y -= Mm(5.0);
}

fn draw_bullet_item(layer: &PdfLayerReference, text: &str, x: Mm, y: &mut Mm, font: &IndirectFontRef) {
    layer.set_fill_color(color_text());
    layer.use_text("•", FONT_SIZE_BODY, x, *y, font);
    
    // Wrap text if too long
    let max_width = 160.0; // mm
    let wrapped_lines = wrap_text(text, max_width);
    
    for (i, line) in wrapped_lines.iter().enumerate() {
        layer.use_text(line, FONT_SIZE_BODY, x + Mm(5.0), *y, font);
        if i < wrapped_lines.len() - 1 {
            *y -= Mm(4.0);
        }
    }
    
    *y -= Mm(4.0);
}

fn draw_page_header(layer: &PdfLayerReference, title: &str, page_num: u32, font_bold: &IndirectFontRef, font: &IndirectFontRef) {
    layer.set_fill_color(color_red());
    layer.use_text(title, FONT_SIZE_HEADING, MARGIN_LEFT, MARGIN_TOP, font_bold);
    
    if page_num > 0 {
        layer.set_fill_color(color_gray());
        let page_text = format!("Page {}", page_num);
        layer.use_text(&page_text, FONT_SIZE_SMALL, MARGIN_RIGHT - Mm(15.0), MARGIN_TOP, font);
    }
    
    layer.set_fill_color(color_text());
}

fn wrap_text(text: &str, max_width: f32) -> Vec<String> {
    // Simple text wrapping - split at max_width characters
    // For production, should use proper text measurement
    let chars_per_line = (max_width / 1.5) as usize; // Rough estimate
    
    let mut lines = Vec::new();
    let mut current_line = String::new();
    
    for word in text.split_whitespace() {
        if current_line.len() + word.len() + 1 > chars_per_line {
            if !current_line.is_empty() {
                lines.push(current_line.clone());
                current_line.clear();
            }
        }
        
        if !current_line.is_empty() {
            current_line.push(' ');
        }
        current_line.push_str(word);
    }
    
    if !current_line.is_empty() {
        lines.push(current_line);
    }
    
    if lines.is_empty() {
        lines.push(text.to_string());
    }
    
    lines
}
