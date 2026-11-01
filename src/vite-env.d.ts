/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_PORTABLE?: string;
  /** Dev-only Mac UI preview (see src/lib/hostPlatform.ts). Ignored by `vite build`. */
  readonly VITE_MAC_PREVIEW?: string;
}
