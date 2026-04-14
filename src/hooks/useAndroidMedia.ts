import { useState, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { MediaFile } from '../types/media';

interface PullResult {
  localPath: string;
  thumbnailPath?: string;
}

/**
 * Hook for managing Android media files (pulling and caching)
 */
export function useAndroidMedia() {
  const [pullingFiles, setPullingFiles] = useState<Set<string>>(new Set());
  const [cachedFiles, setCachedFiles] = useState<Map<string, PullResult>>(new Map());

  /**
   * Pull an Android media file to local cache for viewing
   */
  const pullMediaFile = useCallback(async (media: MediaFile): Promise<PullResult | null> => {
    if (!media.isAndroidFile || !media.androidSerial) {
      console.error('Not an Android file or missing serial');
      return null;
    }

    // Check if already cached
    if (cachedFiles.has(media.filePath)) {
      console.log('[Android Media] File already cached:', media.filePath);
      return cachedFiles.get(media.filePath)!;
    }

    // Check if currently pulling
    if (pullingFiles.has(media.filePath)) {
      console.log('[Android Media] File is already being pulled:', media.filePath);
      return null;
    }

    try {
      // Mark as pulling
      setPullingFiles(prev => new Set(prev).add(media.filePath));

      console.log('[Android Media] Pulling file from device:', media.filePath);
      
      const result = await invoke<PullResult>('pull_android_media_for_viewing', {
        serial: media.androidSerial,
        androidPath: media.filePath,
        mediaType: media.mediaType,
      });

      console.log('[Android Media] File pulled successfully:', {
        localPath: result.localPath,
        thumbnailPath: result.thumbnailPath,
        localPathType: typeof result.localPath,
        hasLocalPath: !!result.localPath
      });

      // Cache the result
      setCachedFiles(prev => new Map(prev).set(media.filePath, result));

      return result;
    } catch (error) {
      console.error('[Android Media] Failed to pull file:', error);
      throw error;
    } finally {
      // Remove from pulling set
      setPullingFiles(prev => {
        const newSet = new Set(prev);
        newSet.delete(media.filePath);
        return newSet;
      });
    }
  }, [cachedFiles, pullingFiles]);

  /**
   * Check if a file is being pulled
   */
  const isPulling = useCallback((filePath: string): boolean => {
    return pullingFiles.has(filePath);
  }, [pullingFiles]);

  /**
   * Get cached file info
   */
  const getCachedFile = useCallback((filePath: string): PullResult | null => {
    return cachedFiles.get(filePath) || null;
  }, [cachedFiles]);

  /**
   * Clear all cached files
   */
  const clearCache = useCallback(() => {
    setCachedFiles(new Map());
  }, []);

  return {
    pullMediaFile,
    isPulling,
    getCachedFile,
    clearCache,
    pullingCount: pullingFiles.size,
    cachedCount: cachedFiles.size,
  };
}
