/**
 * Media protocol utilities for handling large media files
 * Uses Tauri's built-in convertFileSrc for reliable file serving
 */

import { convertFileSrc } from '@tauri-apps/api/core';

/**
 * Convert a file path to use Tauri's asset protocol
 * This uses Tauri's built-in file serving which is reliable and secure
 * 
 * @param filePath - Absolute file path
 * @returns URL using Tauri's asset protocol
 */
export function convertToMediaProtocol(filePath: string): string {
  // Safety check - ensure we have a string
  if (!filePath || typeof filePath !== 'string') {
    console.error('[Media Protocol] Invalid filePath:', filePath, 'type:', typeof filePath);
    return '';
  }
  
  // Normalize path for Windows
  let normalizedPath = filePath.replace(/\\/g, '/');
  
  // Use Tauri's built-in convertFileSrc which handles all the complexity
  const assetUrl = convertFileSrc(normalizedPath);
  
  console.log('[Media Protocol] Converting path:', {
    original: filePath,
    normalized: normalizedPath,
    assetUrl: assetUrl
  });
  
  return assetUrl;
}

/**
 * Check if a file exists and get metadata
 */
export async function getMediaFileInfo(filePath: string) {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<{
      path: string;
      size: number;
      mime_type: string;
      exists: boolean;
    }>('get_media_file_info', { path: filePath });
  } catch (error) {
    console.error('[Media Protocol] Failed to get file info:', error);
    return null;
  }
}

/**
 * Get file as base64 data URL (for smaller files only, <50MB)
 * Useful for files that don't work well with streaming
 */
export async function getFileAsBase64(filePath: string): Promise<string | null> {
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    return await invoke<string>('get_file_as_base64', { path: filePath });
  } catch (error) {
    console.error('[Media Protocol] Failed to get file as base64:', error);
    return null;
  }
}

/**
 * Determine the best protocol to use for a given file
 */
export async function getBestMediaSource(filePath: string): Promise<string> {
  const info = await getMediaFileInfo(filePath);
  
  if (!info || !info.exists) {
    console.warn('[Media Protocol] File does not exist:', filePath);
    return convertToMediaProtocol(filePath); // Try anyway
  }
  
  // For very small files (<5MB images), use base64
  if (info.mime_type.startsWith('image/') && info.size < 5 * 1024 * 1024) {
    const base64 = await getFileAsBase64(filePath);
    if (base64) {
      return base64;
    }
  }
  
  // For everything else, use the streaming media protocol
  return convertToMediaProtocol(filePath);
}
