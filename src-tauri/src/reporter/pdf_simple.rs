// Simple, robust PDF generator - just show all flagged items, period.

use super::{ReportPayload, ReportScope, generate_report_filename};
use printpdf::*;
use std::error::Error;
use std::fs::File;
use std::io::BufWriter;
use std::path::{Path, PathBuf};

const PAGE_WIDTH: f32 = 210.0;
const PAGE_HEIGHT: f32 = 297.0;
const MARGIN: f32 = 20.0;
const BOTTOM_MARGIN: f32 = 30.0;

const FONT_LARGE: f32 = 24.0;
const FONT_MED: f32 = 16.0;
const FONT_BODY: f32 = 11.0;
const FONT_SMALL: f32 = 9.0;

const LINE_SPACING: f32 = 5.0;

pub fn generate(payload: &ReportPayload, reports_dir: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let filename = generate_report_filename(&payload.metadata.case_number, "pdf");
    let filepath = reports_dir.join(&filename);
    
    let (doc, page_idx, layer_idx) = PdfDocument::new("Datapilot Scout Report", Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Page 1");
    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;
    
    let mut y = PAGE_HEIGHT - MARGIN;
    let mut page_idx = page_idx;
    let mut layer_idx = layer_idx;
    
    // HEADER
    let layer = doc.get_page(page_idx).get_layer(layer_idx);
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
    layer.use_text("DATAPILOT", FONT_LARGE, Mm(MARGIN), Mm(y), &font_bold);
    y -= 12.0;
    
    layer.set_fill_color(Color::Rgb(Rgb::new(0.42, 0.54, 1.0, None)));
    layer.use_text("SCOUT", FONT_LARGE, Mm(MARGIN), Mm(y), &font_bold);
    y -= 8.0;
    
    layer.set_fill_color(Color::Rgb(Rgb::new(0.5, 0.5, 0.5, None)));
    layer.use_text("POWERED BY PROJECT HINDSIGHT", FONT_SMALL, Mm(MARGIN), Mm(y), &font);
    y -= 12.0;
    
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
    layer.use_text("Digital Forensic Triage Report", FONT_MED, Mm(MARGIN), Mm(y), &font);
    y -= 20.0;
    
    // CASE INFO
    layer.use_text("CASE INFORMATION", FONT_MED, Mm(MARGIN), Mm(y), &font_bold);
    y -= 8.0;
    
    layer.set_fill_color(Color::Rgb(Rgb::new(0.3, 0.3, 0.3, None)));
    layer.use_text(&format!("Case Number: {}", payload.metadata.case_number), FONT_BODY, Mm(MARGIN + 5.0), Mm(y), &font);
    y -= LINE_SPACING;
    layer.use_text(&format!("Detective: {}", payload.metadata.assigned_detective), FONT_BODY, Mm(MARGIN + 5.0), Mm(y), &font);
    y -= LINE_SPACING;
    layer.use_text(&format!("Generated: {}", payload.metadata.generated_date), FONT_BODY, Mm(MARGIN + 5.0), Mm(y), &font);
    y -= 15.0;
    
    // Count flagged items
    let mut total_flagged = 0;
    
    // Count apps
    if let Some(apps) = payload.all_data.apps.as_array() {
        total_flagged += apps.iter().filter(|a| a.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
    }
    
    // Count browser items
    if let Some(browsers) = payload.all_data.browsers.as_array() {
        for browser in browsers {
            if let Some(history) = browser.get("history").and_then(|h| h.as_array()) {
                total_flagged += history.iter().filter(|h| h.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
            }
            if let Some(downloads) = browser.get("downloads").and_then(|d| d.as_array()) {
                total_flagged += downloads.iter().filter(|d| d.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
            }
            if let Some(creds) = browser.get("credentials").and_then(|c| c.as_array()) {
                total_flagged += creds.iter().filter(|c| c.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
            }
        }
    }
    
    // Count media
    if let Some(media) = payload.all_data.csam.as_array() {
        total_flagged += media.iter().filter(|m| m.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
    }
    
    // Count keywords
    if let Some(keywords) = payload.all_data.keywords.as_array() {
        total_flagged += keywords.iter().filter(|k| k.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).count();
    }
    
    layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
    layer.use_text("FINDINGS SUMMARY", FONT_MED, Mm(MARGIN), Mm(y), &font_bold);
    y -= 8.0;
    layer.set_fill_color(Color::Rgb(Rgb::new(0.3, 0.3, 0.3, None)));
    layer.use_text(&format!("Total Flagged Items: {}", total_flagged), FONT_BODY, Mm(MARGIN + 5.0), Mm(y), &font);
    y -= 20.0;
    
    // NEW PAGE for flagged items
    let (new_page, new_layer) = doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Flagged Evidence");
    page_idx = new_page;
    layer_idx = new_layer;
    y = PAGE_HEIGHT - MARGIN;
    
    let layer = doc.get_page(page_idx).get_layer(layer_idx);
    layer.set_fill_color(Color::Rgb(Rgb::new(0.42, 0.54, 1.0, None)));
    layer.use_text("FLAGGED EVIDENCE DETAILS", FONT_MED, Mm(MARGIN), Mm(y), &font_bold);
    y -= 12.0;
    
    // APPLICATIONS
    if let Some(apps) = payload.all_data.apps.as_array() {
        let flagged_apps: Vec<_> = apps.iter().filter(|a| a.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).collect();
        
        if !flagged_apps.is_empty() {
            let layer = doc.get_page(page_idx).get_layer(layer_idx);
            layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            layer.use_text(&format!("APPLICATIONS ({} flagged)", flagged_apps.len()), FONT_MED, Mm(MARGIN), Mm(y), &font_bold);
            y -= 8.0;
            
            for (idx, app) in flagged_apps.iter().enumerate() {
                if y < BOTTOM_MARGIN + 20.0 {
                    let (new_page, new_layer) = doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Flagged Apps Cont");
                    page_idx = new_page;
                    layer_idx = new_layer;
                    y = PAGE_HEIGHT - MARGIN;
                }
                
                let layer = doc.get_page(page_idx).get_layer(layer_idx);
                let name = app.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let location = app.get("install_path").or_else(|| app.get("location")).and_then(|v| v.as_str()).unwrap_or("Unknown");
                
                layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
                layer.use_text(&format!("{}. {}", idx + 1, name), FONT_BODY, Mm(MARGIN + 3.0), Mm(y), &font_bold);
                y -= LINE_SPACING;
                
                layer.set_fill_color(Color::Rgb(Rgb::new(0.4, 0.4, 0.4, None)));
                layer.use_text(&format!("   Location: {}", location), FONT_SMALL, Mm(MARGIN + 3.0), Mm(y), &font);
                y -= LINE_SPACING;
                
                // Show hash if available
                if let Some(hash) = app.get("hash").or_else(|| app.get("sha256")).and_then(|v| v.as_str()) {
                    layer.use_text(&format!("   Hash: {}", hash), FONT_SMALL, Mm(MARGIN + 3.0), Mm(y), &font);
                    y -= LINE_SPACING;
                }
                
                y -= LINE_SPACING;
            }
            
            y -= 10.0;
        }
    }
    
    // BROWSER HISTORY
    if let Some(browsers) = payload.all_data.browsers.as_array() {
        let mut all_history = Vec::new();
        
        for browser in browsers {
            let browser_name = browser.get("browserName").or_else(|| browser.get("browser")).and_then(|v| v.as_str()).unwrap_or("Unknown");
            
            if let Some(history) = browser.get("history").and_then(|h| h.as_array()) {
                for item in history {
                    if item.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false) {
                        all_history.push((browser_name, item));
                    }
                }
            }
        }
        
        if !all_history.is_empty() {
            if y < BOTTOM_MARGIN + 20.0 {
                let (new_page, new_layer) = doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Browser History");
                page_idx = new_page;
                layer_idx = new_layer;
                y = PAGE_HEIGHT - MARGIN;
            }
            
            let layer = doc.get_page(page_idx).get_layer(layer_idx);
            layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            layer.use_text(&format!("BROWSER HISTORY ({} flagged)", all_history.len()), FONT_MED, Mm(MARGIN), Mm(y), &font_bold);
            y -= 8.0;
            
            for (idx, (browser_name, item)) in all_history.iter().enumerate() {
                if y < BOTTOM_MARGIN + 25.0 {
                    let (new_page, new_layer) = doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Browser History Cont");
                    page_idx = new_page;
                    layer_idx = new_layer;
                    y = PAGE_HEIGHT - MARGIN;
                }
                
                let layer = doc.get_page(page_idx).get_layer(layer_idx);
                let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("Unknown");
                let title = item.get("title").and_then(|v| v.as_str()).unwrap_or("");
                let visit_time = item.get("lastVisitTime").or_else(|| item.get("last_visit_time")).and_then(|v| v.as_str()).unwrap_or("Unknown");
                
                layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
                layer.use_text(&format!("{}. {} - {}", idx + 1, browser_name, if title.is_empty() { url } else { title }), FONT_BODY, Mm(MARGIN + 3.0), Mm(y), &font_bold);
                y -= LINE_SPACING;
                
                layer.set_fill_color(Color::Rgb(Rgb::new(0.4, 0.4, 0.4, None)));
                if !title.is_empty() {
                    layer.use_text(&format!("   URL: {}", url), FONT_SMALL, Mm(MARGIN + 3.0), Mm(y), &font);
                    y -= LINE_SPACING;
                }
                layer.use_text(&format!("   Last Visit: {}", visit_time), FONT_SMALL, Mm(MARGIN + 3.0), Mm(y), &font);
                y -= LINE_SPACING;
                
                y -= LINE_SPACING;
            }
            
            y -= 10.0;
        }
    }
    
    // BROWSER DOWNLOADS
    if let Some(browsers) = payload.all_data.browsers.as_array() {
        let mut all_downloads = Vec::new();
        
        for browser in browsers {
            let browser_name = browser.get("browserName").or_else(|| browser.get("browser")).and_then(|v| v.as_str()).unwrap_or("Unknown");
            
            if let Some(downloads) = browser.get("downloads").and_then(|d| d.as_array()) {
                for item in downloads {
                    if item.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false) {
                        all_downloads.push((browser_name, item));
                    }
                }
            }
        }
        
        if !all_downloads.is_empty() {
            if y < BOTTOM_MARGIN + 20.0 {
                let (new_page, new_layer) = doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Downloads");
                page_idx = new_page;
                layer_idx = new_layer;
                y = PAGE_HEIGHT - MARGIN;
            }
            
            let layer = doc.get_page(page_idx).get_layer(layer_idx);
            layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            layer.use_text(&format!("BROWSER DOWNLOADS ({} flagged)", all_downloads.len()), FONT_MED, Mm(MARGIN), Mm(y), &font_bold);
            y -= 8.0;
            
            for (idx, (browser_name, item)) in all_downloads.iter().enumerate() {
                if y < BOTTOM_MARGIN + 25.0 {
                    let (new_page, new_layer) = doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Downloads Cont");
                    page_idx = new_page;
                    layer_idx = new_layer;
                    y = PAGE_HEIGHT - MARGIN;
                }
                
                let layer = doc.get_page(page_idx).get_layer(layer_idx);
                let target_path = item.get("targetPath").or_else(|| item.get("target_path")).and_then(|v| v.as_str()).unwrap_or("Unknown");
                let url = item.get("url").and_then(|v| v.as_str()).unwrap_or("Unknown");
                
                layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
                layer.use_text(&format!("{}. {} Download", idx + 1, browser_name), FONT_BODY, Mm(MARGIN + 3.0), Mm(y), &font_bold);
                y -= LINE_SPACING;
                
                layer.set_fill_color(Color::Rgb(Rgb::new(0.4, 0.4, 0.4, None)));
                layer.use_text(&format!("   File: {}", target_path), FONT_SMALL, Mm(MARGIN + 3.0), Mm(y), &font);
                y -= LINE_SPACING;
                layer.use_text(&format!("   From: {}", url), FONT_SMALL, Mm(MARGIN + 3.0), Mm(y), &font);
                y -= LINE_SPACING;
                
                y -= LINE_SPACING;
            }
            
            y -= 10.0;
        }
    }
    
    // MEDIA FILES
    if let Some(media) = payload.all_data.csam.as_array() {
        let flagged_media: Vec<_> = media.iter().filter(|m| m.get("isFlagged").and_then(|v| v.as_bool()).unwrap_or(false)).collect();
        
        if !flagged_media.is_empty() {
            if y < BOTTOM_MARGIN + 20.0 {
                let (new_page, new_layer) = doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Media Files");
                page_idx = new_page;
                layer_idx = new_layer;
                y = PAGE_HEIGHT - MARGIN;
            }
            
            let layer = doc.get_page(page_idx).get_layer(layer_idx);
            layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
            layer.use_text(&format!("MEDIA FILES ({} flagged)", flagged_media.len()), FONT_MED, Mm(MARGIN), Mm(y), &font_bold);
            y -= 8.0;
            
            for (idx, item) in flagged_media.iter().enumerate() {
                if y < BOTTOM_MARGIN + 25.0 {
                    let (new_page, new_layer) = doc.add_page(Mm(PAGE_WIDTH), Mm(PAGE_HEIGHT), "Media Cont");
                    page_idx = new_page;
                    layer_idx = new_layer;
                    y = PAGE_HEIGHT - MARGIN;
                }
                
                let layer = doc.get_page(page_idx).get_layer(layer_idx);
                let file_name = item.get("fileName").or_else(|| item.get("file_name")).and_then(|v| v.as_str()).unwrap_or("Unknown");
                let file_path = item.get("filePath").or_else(|| item.get("file_path")).and_then(|v| v.as_str()).unwrap_or("Unknown");
                let hash = item.get("hash").or_else(|| item.get("sha256")).and_then(|v| v.as_str());
                
                layer.set_fill_color(Color::Rgb(Rgb::new(0.0, 0.0, 0.0, None)));
                layer.use_text(&format!("{}. {}", idx + 1, file_name), FONT_BODY, Mm(MARGIN + 3.0), Mm(y), &font_bold);
                y -= LINE_SPACING;
                
                layer.set_fill_color(Color::Rgb(Rgb::new(0.4, 0.4, 0.4, None)));
                layer.use_text(&format!("   Path: {}", file_path), FONT_SMALL, Mm(MARGIN + 3.0), Mm(y), &font);
                y -= LINE_SPACING;
                
                if let Some(hash_val) = hash {
                    layer.use_text(&format!("   Hash: {}", hash_val), FONT_SMALL, Mm(MARGIN + 3.0), Mm(y), &font);
                    y -= LINE_SPACING;
                }
                
                y -= LINE_SPACING;
            }
        }
    }
    
    // Save
    doc.save(&mut BufWriter::new(File::create(&filepath)?))?;
    Ok(filepath)
}
