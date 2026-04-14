use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeBase {
    pub version: String,
    pub last_updated: String,
    pub applications: Vec<AppSignature>,
    pub keyword_rules: HashMap<String, Vec<String>>,
    pub manufacturer_defaults: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSignature {
    pub product_names: Vec<String>,
    pub company_names: Vec<String>,
    pub executable_names: Vec<String>,
    pub keywords: Vec<String>,
    pub investigative_category: String,
    pub function_category: String,
}

#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub investigative_category: String,
    pub function_category: String,
    pub confidence: f32,
    pub match_reason: String,
}

pub struct AppClassifier {
    kb: KnowledgeBase,
}

impl AppClassifier {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Try multiple locations for the knowledge base
        let possible_paths = vec![
            "knowledge_base.json",
            "../knowledge_base.json",
            "../../knowledge_base.json",
        ];
        
        let mut kb_path = None;
        for path in &possible_paths {
            if Path::new(path).exists() {
                kb_path = Some(*path);
                break;
            }
        }
        
        let kb_path = match kb_path {
            Some(path) => path,
            None => {
                eprintln!("WARNING: knowledge_base.json not found!");
                eprintln!("Current dir: {}", std::env::current_dir()?.display());
                eprintln!("Tried paths: {:?}", possible_paths);
                eprintln!("Using minimal fallback KB");
                return Ok(Self {
                    kb: Self::create_minimal_kb(),
                });
            }
        };

        eprintln!("Loading knowledge base from: {}", kb_path);
        let kb_content = fs::read_to_string(kb_path)
            .map_err(|e| {
                eprintln!("ERROR reading knowledge_base.json: {}", e);
                e
            })?;
        
        let kb: KnowledgeBase = serde_json::from_str(&kb_content)
            .map_err(|e| {
                eprintln!("ERROR parsing knowledge_base.json: {}", e);
                e
            })?;
        
        eprintln!("✓ Loaded knowledge base v{} with {} app signatures", 
                  kb.version, kb.applications.len());
        
        Ok(Self { kb })
    }

    fn create_minimal_kb() -> KnowledgeBase {
        KnowledgeBase {
            version: "0.1-fallback".to_string(),
            last_updated: "2025-12-05".to_string(),
            applications: vec![],
            keyword_rules: HashMap::new(),
            manufacturer_defaults: HashMap::new(),
        }
    }

    pub fn classify(&self, 
                    product_name: &str, 
                    company_name: &Option<String>,
                    executable_name: &str,
                    install_path: &str) -> ClassificationResult {
        
        let product_lower = product_name.to_lowercase();
        let company_lower = company_name.as_ref()
            .map(|c| c.to_lowercase())
            .unwrap_or_default();
        let exe_lower = executable_name.to_lowercase();
        let path_lower = install_path.to_lowercase();

        // Feature 1: Exact Product Name Match (Weight: 1.0)
        for sig in &self.kb.applications {
            for sig_product in &sig.product_names {
                if product_lower == sig_product.to_lowercase() {
                    return ClassificationResult {
                        investigative_category: sig.investigative_category.clone(),
                        function_category: sig.function_category.clone(),
                        confidence: 1.0,
                        match_reason: format!("Exact product name match: {}", sig_product),
                    };
                }
            }
        }

        // Feature 2: Partial Product Name Match (Weight: 0.95)
        for sig in &self.kb.applications {
            for sig_product in &sig.product_names {
                let sig_lower = sig_product.to_lowercase();
                if product_lower.contains(&sig_lower) || sig_lower.contains(&product_lower) {
                    if product_lower.len() > 3 && sig_lower.len() > 3 { // Avoid short matches
                        return ClassificationResult {
                            investigative_category: sig.investigative_category.clone(),
                            function_category: sig.function_category.clone(),
                            confidence: 0.95,
                            match_reason: format!("Partial product name match: {}", sig_product),
                        };
                    }
                }
            }
        }

        // Feature 3: Company Name + Keywords Match (Weight: 0.85)
        if !company_lower.is_empty() {
            for sig in &self.kb.applications {
                for sig_company in &sig.company_names {
                    if company_lower.contains(&sig_company.to_lowercase()) {
                        // Check if keywords also match
                        for keyword in &sig.keywords {
                            let kw_lower = keyword.to_lowercase();
                            if product_lower.contains(&kw_lower) || 
                               exe_lower.contains(&kw_lower) ||
                               path_lower.contains(&kw_lower) {
                                return ClassificationResult {
                                    investigative_category: sig.investigative_category.clone(),
                                    function_category: sig.function_category.clone(),
                                    confidence: 0.85,
                                    match_reason: format!("Company + keyword match: {} + {}", sig_company, keyword),
                                };
                            }
                        }
                    }
                }
            }
        }

        // Feature 4: Executable Name Match (Weight: 0.80)
        for sig in &self.kb.applications {
            for sig_exe in &sig.executable_names {
                if exe_lower == sig_exe.to_lowercase() {
                    return ClassificationResult {
                        investigative_category: sig.investigative_category.clone(),
                        function_category: sig.function_category.clone(),
                        confidence: 0.80,
                        match_reason: format!("Executable name match: {}", sig_exe),
                    };
                }
            }
        }

        // Feature 5: Keyword-Based Categorization (Weight: 0.70)
        let combined_text = format!("{} {} {} {}", 
                                   product_lower, company_lower, exe_lower, path_lower);
        
        for (category, keywords) in &self.kb.keyword_rules {
            for keyword in keywords {
                if combined_text.contains(&keyword.to_lowercase()) {
                    // Determine function category based on keyword
                    let function_cat = self.infer_function_category(keyword);
                    return ClassificationResult {
                        investigative_category: category.clone(),
                        function_category: function_cat,
                        confidence: 0.70,
                        match_reason: format!("Keyword match: {}", keyword),
                    };
                }
            }
        }

        // Feature 6: Manufacturer Default (Weight: 0.60)
        if !company_lower.is_empty() {
            for (manufacturer, default_cat) in &self.kb.manufacturer_defaults {
                if company_lower.contains(&manufacturer.to_lowercase()) {
                    return ClassificationResult {
                        investigative_category: default_cat.clone(),
                        function_category: "SystemUtility".to_string(),
                        confidence: 0.60,
                        match_reason: format!("Manufacturer default: {}", manufacturer),
                    };
                }
            }
        }

        // Default: UNKNOWN (Confidence: 0.0)
        ClassificationResult {
            investigative_category: "UNKNOWN".to_string(),
            function_category: "Unknown".to_string(),
            confidence: 0.0,
            match_reason: "No matching patterns found".to_string(),
        }
    }

    fn infer_function_category(&self, keyword: &str) -> String {
        let kw_lower = keyword.to_lowercase();
        
        if kw_lower.contains("tor") || kw_lower.contains("vpn") || kw_lower.contains("encrypt") {
            "AnonymityTool".to_string()
        } else if kw_lower.contains("torrent") || kw_lower.contains("p2p") {
            "FileSharing".to_string()
        } else if kw_lower.contains("bitcoin") || kw_lower.contains("crypto") {
            "CryptoWallet".to_string()
        } else if kw_lower.contains("message") || kw_lower.contains("chat") {
            "Messaging".to_string()
        } else if kw_lower.contains("browser") || kw_lower.contains("chrome") || kw_lower.contains("firefox") {
            "Browser".to_string()
        } else {
            "General".to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classification() {
        let classifier = AppClassifier::new().unwrap();
        
        // Test exact match
        let result = classifier.classify(
            "Google Chrome",
            &Some("Google LLC".to_string()),
            "chrome.exe",
            "C:\\Program Files\\Google\\Chrome"
        );
        assert!(result.confidence >= 0.95);
        assert_eq!(result.investigative_category, "GENERAL_PRODUCTIVITY");
    }
}
