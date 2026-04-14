export interface QuestionableApp {
  name: string;
  category: AppCategory;
  install_path: string;
  version: string;
  install_date: string | null;
  publisher: string | null;
  artifact_paths: string[];
  investigative_category?: string; // Optional - may be undefined from backend
  function_category?: string; // Optional - may be undefined from backend
  confidence: number;
}

export type AppCategory = 
  | "SocialMedia"
  | "Messaging"
  | "Gaming"
  | "PeerToPeer"
  | "DarkWeb"
  | "VPN" 
  | "VirtualMachine"
  | "WebBrowser"
  | "CloudStorage"
  | "CryptoPayment"
  | "Cleaner"
  | "Encryption" 
  | "AntiForensics"
  | "RemoteAccess"
  | "Utilities"
  | "Productivity"
  | "Development"
  | "Multimedia"
  | "Unknown";

export const AppCategoryLabels: Record<AppCategory, string> = {
  SocialMedia: "Social Media",
  Messaging: "Messaging",
  Gaming: "Gaming",
  PeerToPeer: "P2P / File Sharing",
  DarkWeb: "Dark Web / Anonymity",
  VPN: "VPN",
  VirtualMachine: "Virtual Machine",
  WebBrowser: "Browser",
  CloudStorage: "Cloud Storage",
  CryptoPayment: "Crypto / Payment",
  Cleaner: "System Cleaner",
  Encryption: "Encryption",
  AntiForensics: "Anti-Forensic",
  RemoteAccess: "Remote Access",
  Utilities: "Utilities",
  Productivity: "Productivity",
  Development: "Development",
  Multimedia: "Multimedia",
  Unknown: "Unknown"
};

export const AppCategoryColors: Record<AppCategory, string> = {
  SocialMedia: "var(--color-info)",
  Messaging: "var(--color-info)",
  Gaming: "var(--color-success)",
  PeerToPeer: "var(--color-danger)",
  DarkWeb: "var(--color-danger)",
  VPN: "var(--color-accent-amber)",
  VirtualMachine: "var(--color-accent-amber)",
  WebBrowser: "var(--color-success)",
  CloudStorage: "var(--color-accent-amber)",
  CryptoPayment: "var(--color-accent-amber)",
  Cleaner: "var(--color-danger)",
  Encryption: "var(--color-accent-amber)",
  AntiForensics: "var(--color-danger)",
  RemoteAccess: "var(--color-accent-amber)",
  Utilities: "var(--color-success)",
  Productivity: "var(--color-success)",
  Development: "var(--color-success)",
  Multimedia: "var(--color-success)",
  Unknown: "var(--color-text-muted)"
};

export const AppCategoryRiskLevels: Record<AppCategory, string> = {
  SocialMedia: "MEDIUM",
  Messaging: "MEDIUM",
  Gaming: "LOW",
  PeerToPeer: "HIGH",
  DarkWeb: "CRITICAL",
  VPN: "HIGH",
  VirtualMachine: "HIGH",
  WebBrowser: "LOW",
  CloudStorage: "MEDIUM",
  CryptoPayment: "HIGH",
  Cleaner: "CRITICAL",
  Encryption: "HIGH",
  AntiForensics: "CRITICAL",
  RemoteAccess: "HIGH",
  Utilities: "LOW",
  Productivity: "LOW",
  Development: "LOW",
  Multimedia: "LOW",
  Unknown: "UNKNOWN"
};
