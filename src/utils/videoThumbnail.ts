/**
 * Generate video thumbnail using HTML5 video element
 * Captures first frame of video without requiring ffmpeg
 */

/**
 * Generate a thumbnail from a video file
 * @param videoUrl - URL to the video file (can be asset:// protocol)
 * @param width - Thumbnail width (default 300px)
 * @returns Base64 data URL of the thumbnail, or null if failed
 */
export async function generateVideoThumbnail(
  videoUrl: string,
  width: number = 300
): Promise<string | null> {
  return new Promise((resolve) => {
    try {
      // Create video element
      const video = document.createElement('video');
      // Do NOT set crossOrigin — Tauri asset:// protocol is same-origin
      // Setting 'anonymous' taints the canvas and blocks toDataURL()
      video.preload = 'metadata';
      video.muted = true; // Mute to allow autoplay
      
      // Set up error handlers
      video.onerror = () => {
        resolve(null);
      };

      // Timeout after 10 seconds
      const timeout = setTimeout(() => {
        video.remove();
        resolve(null);
      }, 10000);

      video.onseeked = () => {
        clearTimeout(timeout);
        try {
          const canvas = document.createElement('canvas');
          const context = canvas.getContext('2d');
          
          if (!context) {
            resolve(null);
            return;
          }

          const aspectRatio = video.videoWidth / video.videoHeight;
          canvas.width = width;
          canvas.height = Math.round(width / aspectRatio);

          context.drawImage(video, 0, 0, canvas.width, canvas.height);
          const thumbnailDataUrl = canvas.toDataURL('image/jpeg', 0.85);

          video.remove();
          resolve(thumbnailDataUrl);
        } catch (error) {
          console.error('[Video Thumbnail] Canvas capture failed:', error);
          resolve(null);
        }
      };

      video.onloadeddata = () => {
        clearTimeout(timeout);
        try {
          const seekTime = Math.min(1.0, video.duration * 0.1);
          video.currentTime = seekTime;
        } catch (error) {
          resolve(null);
        }
      };

      // Start loading video
      video.src = videoUrl;
      video.load();

    } catch (error) {
      console.error('[Video Thumbnail] Error:', error);
      resolve(null);
    }
  });
}

/**
 * Cache for generated video thumbnails (in-memory)
 */
const thumbnailCache = new Map<string, string>();

/**
 * Get or generate video thumbnail with caching
 */
export async function getVideoThumbnail(
  videoUrl: string,
  width: number = 300
): Promise<string | null> {
  // Check cache first
  const cacheKey = `${videoUrl}:${width}`;
  if (thumbnailCache.has(cacheKey)) {
    return thumbnailCache.get(cacheKey)!;
  }

  // Generate thumbnail
  const thumbnail = await generateVideoThumbnail(videoUrl, width);
  
  // Cache if successful
  if (thumbnail) {
    thumbnailCache.set(cacheKey, thumbnail);
  }

  return thumbnail;
}

/**
 * Clear thumbnail cache
 */
export function clearVideoThumbnailCache(): void {
  thumbnailCache.clear();
}
