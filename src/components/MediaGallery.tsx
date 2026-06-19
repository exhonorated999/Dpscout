import React, { useState, useRef, useEffect } from 'react';
import { MediaFile } from '../types/media';
import { Button } from './Button';
import './MediaGallery.css';
import { invoke, convertFileSrc } from '@tauri-apps/api/core';
import { convertToMediaProtocol } from '../utils/mediaProtocol';
import { LazyThumbnail } from './LazyThumbnail';
import { useAndroidMedia } from '../hooks/useAndroidMedia';
import { getVideoThumbnail } from '../utils/videoThumbnail';

// ─── Module-level persistent thumbnail caches ────────────────────────────
// These survive MediaGallery mount/unmount cycles, so closing and
// reopening the Media Explorer does NOT re-fetch thumbnails that have
// already been generated. Cleared on app restart (not persisted to disk).
//
// Keyed by AFC virtual path (e.g. "/DCIM/106APPLE/IMG_6785.MOV") or
// local absolute path. data:image/jpeg;base64,... data URLs as values.
//
// Both maps are exported so the App-level "Clear Cache" handler can wipe
// them if/when the user explicitly asks for a fresh fetch.
export const persistentVideoThumbCache = new Map<string, string>();
export const persistentImageThumbCache = new Map<string, string>();
// Larger previews used by the Media Detail modal for iOS AFC images.
// Separate cache so the small grid thumbs don't get evicted by full-size
// loads, and so the modal can fall back to the small thumb instantly
// while the full-res preview is fetched.
export const persistentIosFullCache = new Map<string, string>();

interface MediaGalleryProps {
  media: MediaFile[];
  isScanning: boolean;
  onStartScan: () => void;
  onClearCache: () => void;
  onClose: () => void;
  onToggleFlag?: (itemId: string) => void;
  isFlagged?: (itemId: string) => boolean;
}

type MediaCategory = 'all' | 'images' | 'videos' | 'flagged';

export const MediaGallery: React.FC<MediaGalleryProps> = ({ 
  media, 
  isScanning, 
  onStartScan,
  onClearCache,
  onClose,
  onToggleFlag,
  isFlagged
}) => {
  const [selectedMedia, setSelectedMedia] = useState<MediaFile | null>(null);
  const [activeCategory, setActiveCategory] = useState<MediaCategory>('all');
  const [playingVideo, setPlayingVideo] = useState<MediaFile | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const ITEMS_PER_PAGE = 250;
  
  // Android media management
  const { pullMediaFile, isPulling, getCachedFile } = useAndroidMedia();
  
  // Batch-generated video thumbnails: filePath -> cached thumbnail path
  const [videoThumbnailMap, setVideoThumbnailMap] = useState<Map<string, string>>(
    () => new Map(persistentVideoThumbCache)
  );

  // Extension-based type sets for reliable classification
  const IMAGE_EXTS = new Set(['jpg','jpeg','png','gif','bmp','tiff','tif','webp','heic','heif','ico','raw','cr2','nef','arw','svg']);
  const VIDEO_EXTS = new Set(['mp4','avi','mov','wmv','flv','mkv','webm','m4v','mpg','mpeg','3gp','ogv','ts','mts']);

  // Correct mediaType using file extension (backend may have wrong value in some edge cases)
  const getReliableType = (m: MediaFile): 'image' | 'video' | 'unknown' => {
    const ext = (m.extension || m.fileName?.split('.').pop() || '').toLowerCase();
    if (IMAGE_EXTS.has(ext)) return 'image';
    if (VIDEO_EXTS.has(ext)) return 'video';
    return m.mediaType; // fallback to whatever backend said
  };

  // Separate media by type (extension-verified)
  const images = media.filter(m => getReliableType(m) === 'image');
  const videos = media.filter(m => getReliableType(m) === 'video');
  const flaggedMedia = media.filter(m => m.flags && Array.isArray(m.flags) && m.flags.length > 0);
  const criticalCount = media.filter(m => 
    m.flags && Array.isArray(m.flags) && m.flags.some(f => f.severity === 'critical')
  ).length;

  // Sequential video thumbnail generation — processes one video at a time
  // Uses ffmpeg backend first, falls back to browser canvas
  const videoThumbnailMapRef = React.useRef(videoThumbnailMap);
  videoThumbnailMapRef.current = videoThumbnailMap;
  
  useEffect(() => {
    // Skip videos that are remote (Android-shell-served or iOS AFC virtual
    // paths). ffmpeg + canvas both need a real local file path; AFC
    // paths like "/DCIM/106APPLE/IMG_6785.MOV" produce os-error-3 noise
    // and asset.localhost 403s. iOS AFC video thumbs would require a
    // dedicated daemon-side ffmpeg pipeline — until then, fall through
    // to the camera placeholder.
    const localVideos = videos.filter(
      v => !v.isAndroidFile && !v.isIosAfcFile && !v.thumbnailPath
    );
    console.log(`[VideoThumb] Effect fired: ${videos.length} videos, ${localVideos.length} local without thumb`);
    if (localVideos.length === 0) return;
    
    const needed = localVideos.filter(v => !videoThumbnailMapRef.current.has(v.filePath));
    console.log(`[VideoThumb] Needed: ${needed.length} (not yet in map)`);
    if (needed.length === 0) return;

    let cancelled = false;
    
    const processQueue = async () => {
      if (cancelled) { console.log('[VideoThumb] Queue cancelled before start'); return; }
      console.log(`[VideoThumb] Queue starting for ${needed.length} videos`);
      
      const newMap = new Map(videoThumbnailMapRef.current);
      let generated = 0;
      
      for (let i = 0; i < needed.length; i++) {
        const video = needed[i];
        if (cancelled) break;
        
        console.log(`[VideoThumb] [${i+1}/${needed.length}] Processing: ${video.fileName}`);
        
        // Try 1: Backend ffmpeg
        try {
          const result = await invoke<string>('generate_thumbnail', { 
            filePath: video.filePath, 
            mediaType: 'video' 
          });
          if (result && !cancelled) {
            console.log(`[VideoThumb] [${i+1}] ffmpeg OK: ${video.fileName}`);
            newMap.set(video.filePath, result);
            persistentVideoThumbCache.set(video.filePath, result);
            generated++;
            setVideoThumbnailMap(new Map(newMap));
            continue;
          }
        } catch (err) {
          console.warn(`[VideoThumb] [${i+1}] ffmpeg FAIL: ${video.fileName}`, err);
        }
        
        if (cancelled) break;
        
        // Try 2: Browser canvas capture
        try {
          const videoUrl = convertToMediaProtocol(video.filePath);
          const thumb = await getVideoThumbnail(videoUrl, 300);
          if (thumb && !cancelled) {
            console.log(`[VideoThumb] [${i+1}] canvas OK: ${video.fileName}`);
            newMap.set(video.filePath, thumb);
            persistentVideoThumbCache.set(video.filePath, thumb);
            generated++;
            setVideoThumbnailMap(new Map(newMap));
          } else {
            console.warn(`[VideoThumb] [${i+1}] canvas returned null: ${video.fileName}`);
          }
        } catch (err) {
          console.warn(`[VideoThumb] [${i+1}] canvas FAIL: ${video.fileName}`, err);
        }
      }
      
      console.log(`[VideoThumb] Queue complete: ${generated}/${needed.length} thumbnails generated`);
    };

    // Small delay to let scan finish settling
    const timer = setTimeout(processQueue, 500);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [videos.length]); // Re-run when video count changes

  // ── iOS AFC video thumbnails ──
  // The walk emits AFC virtual paths like /DCIM/106APPLE/IMG_6785.MOV that
  // can't be touched by ffmpeg directly. Instead, ask the daemon to pipe
  // AFC bytes through ffmpeg and hand us back a data-URL JPEG. We run this
  // in serial (one AFC connection on the device) and slowly — the scan
  // walk is already saturating AFC, so we yield aggressively between calls.
  //
  // GUARD against React.StrictMode double-effect-invocation. Without this,
  // dev mode spawns TWO concurrent queues that hammer the daemon with the
  // same paths in parallel, multiplying AFC contention and producing
  // duplicate "Queue starting for N videos" logs.
  const afcQueueRunningRef = React.useRef(false);
  useEffect(() => {
    const afcVideos = videos.filter(
      v => v.isIosAfcFile && !videoThumbnailMapRef.current.has(v.filePath)
    );
    console.log(`[AfcThumb] Effect fired: ${afcVideos.length} AFC videos without thumb`);
    if (afcVideos.length === 0) return;
    if (afcQueueRunningRef.current) {
      console.log('[AfcThumb] Queue already running — skipping duplicate StrictMode invocation');
      return;
    }

    let cancelled = false;
    const processAfcQueue = async () => {
      if (cancelled) return;
      afcQueueRunningRef.current = true;

      // ─── PRIORITY GATE ────────────────────────────────────────────
      // Auto-hash flags are the highest-priority investigative signal.
      // Hold the (slow, lock-contending) AFC video queue until every
      // flagged AFC image has either resolved or definitively failed.
      // This guarantees CSAM hits render FIRST, not last.
      const flaggedAfcImages = media.filter(
        m => m.isIosAfcFile
          && m.flags && Array.isArray(m.flags) && m.flags.length > 0
          && getReliableType(m) === 'image'
      );
      if (flaggedAfcImages.length > 0) {
        console.log(`[AfcThumb] Priority gate: waiting on ${flaggedAfcImages.length} flagged image thumbs before starting video queue`);
        const gateDeadline = Date.now() + 90_000; // hard cap 90s so we never block forever
        while (!cancelled && Date.now() < gateDeadline) {
          const pending = flaggedAfcImages.filter(
            m => !persistentImageThumbCache.has(m.filePath)
          );
          if (pending.length === 0) {
            console.log('[AfcThumb] Priority gate cleared — all flagged image thumbs in cache');
            break;
          }
          await new Promise(r => setTimeout(r, 500));
        }
        if (cancelled) return;
      }

      console.log(`[AfcThumb] Queue starting for ${afcVideos.length} videos`);
      const newMap = new Map(videoThumbnailMapRef.current);
      let generated = 0;
      let consecutiveFails = 0;

      try {
        for (let i = 0; i < afcVideos.length; i++) {
          if (cancelled) break;
          // After 3 consecutive failures, back off for a while — AFC is
          // probably saturated by the walk. Don't hammer it.
          if (consecutiveFails >= 3) {
            console.warn(`[AfcThumb] ${consecutiveFails} fails in a row, sleeping 5s`);
            await new Promise(r => setTimeout(r, 5000));
            consecutiveFails = 0;
          }
          const video = afcVideos[i];
          console.log(`[AfcThumb] [${i+1}/${afcVideos.length}] Requesting: ${video.fileName} (${(video.fileSize / 1024 / 1024).toFixed(1)} MB)`);
          try {
            const result = await invoke<{ dataUrl: string }>('get_ios_afc_video_thumbnail', {
              udid: video.iosUdid || null,
              path: video.filePath,
              maxDim: 320,
            });
            if (result?.dataUrl && !cancelled) {
              console.log(`[AfcThumb] [${i+1}] OK: ${video.fileName}`);
              newMap.set(video.filePath, result.dataUrl);
              persistentVideoThumbCache.set(video.filePath, result.dataUrl);
              generated++;
              setVideoThumbnailMap(new Map(newMap));
              consecutiveFails = 0;
            } else {
              consecutiveFails++;
            }
          } catch (err) {
            console.warn(`[AfcThumb] [${i+1}] FAIL: ${video.fileName}`, err);
            consecutiveFails++;
          }
          // Yield so other AFC operations (Range requests for the video
          // player) can interleave between thumbnail generations.
          await new Promise(r => setTimeout(r, 250));
        }
      } finally {
        afcQueueRunningRef.current = false;
        console.log(`[AfcThumb] Queue complete: ${generated}/${afcVideos.length} thumbnails generated`);
      }
    };

    // Bigger delay than local thumbs — AFC is shared with the walk and
    // we don't want to fight it from the moment the first video shows up.
    const timer = setTimeout(processAfcQueue, 1500);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [videos.length]);

  // Get filtered media based on active category
  const getFilteredMedia = (): MediaFile[] => {
    switch (activeCategory) {
      case 'images': return images;
      case 'videos': return videos;
      case 'flagged': return flaggedMedia;
      default: {
        // ALL MEDIA: sort images first, then videos, to avoid intermixing
        return [...media].sort((a, b) => {
          if (a.mediaType === b.mediaType) return 0;
          if (a.mediaType === 'image') return -1;
          return 1;
        });
      }
    }
  };

  const filteredMedia = getFilteredMedia();
  
  // Pagination
  const totalPages = Math.ceil(filteredMedia.length / ITEMS_PER_PAGE);
  const startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
  const endIndex = startIndex + ITEMS_PER_PAGE;
  const paginatedMedia = filteredMedia.slice(startIndex, endIndex);

  // Reset to page 1 when category changes
  const handleCategoryChange = (category: MediaCategory) => {
    setActiveCategory(category);
    setCurrentPage(1);
  };

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical': return 'var(--color-danger)';
      case 'high': return 'var(--color-accent-amber)';
      case 'medium': return 'var(--color-info)';
      case 'low': return 'var(--color-success)';
      default: return 'var(--color-text-muted)';
    }
  };

  if (media.length === 0 && !isScanning) {
    return (
      <div className="media-gallery-empty">
        <div className="empty-state">
          <div className="empty-icon">🖼️</div>
          <h2>No Media Scanned</h2>
          <p>Start a media scan to analyze images and videos on the target system</p>
          <Button variant="primary" size="lg" glow onClick={onStartScan}>
            🔍 Start Media Scan
          </Button>
        </div>
      </div>
    );
  }

  const handleMediaClick = async (mediaItem: MediaFile) => {
    // For Android files, pull them first before viewing
    if (mediaItem.isAndroidFile) {
      try {
        const cachedFile = getCachedFile(mediaItem.filePath);
        
        if (!cachedFile && !isPulling(mediaItem.filePath)) {
          console.log('[Media Gallery] Pulling Android file for viewing...');
          const pullResult = await pullMediaFile(mediaItem);
          
          if (pullResult) {
            // Update the media item with local paths
            const updatedMedia: MediaFile = {
              ...mediaItem,
              localCachePath: pullResult.localPath,
              thumbnailPath: pullResult.thumbnailPath || mediaItem.thumbnailPath,
            };
            
            const pullExt = (mediaItem.extension || mediaItem.fileName?.split('.').pop() || '').toLowerCase();
            const isPullVideo = ['mp4','avi','mov','wmv','flv','mkv','webm','m4v','mpg','mpeg','3gp','ogv','ts','mts'].includes(pullExt);
            if (isPullVideo) {
              setPlayingVideo(updatedMedia);
            } else {
              setSelectedMedia(updatedMedia);
            }
          }
        } else if (cachedFile) {
          // Use cached file
          const updatedMedia: MediaFile = {
            ...mediaItem,
            localCachePath: cachedFile.localPath,
            thumbnailPath: cachedFile.thumbnailPath || mediaItem.thumbnailPath,
          };
          
          const cacheExt = (mediaItem.extension || mediaItem.fileName?.split('.').pop() || '').toLowerCase();
          const isCacheVideo = ['mp4','avi','mov','wmv','flv','mkv','webm','m4v','mpg','mpeg','3gp','ogv','ts','mts'].includes(cacheExt);
          if (isCacheVideo) {
            setPlayingVideo(updatedMedia);
          } else {
            setSelectedMedia(updatedMedia);
          }
        }
      } catch (error) {
        console.error('[Media Gallery] Failed to pull Android file:', error);
        alert(`Failed to load file from Android device: ${error}`);
      }
    } else {
      // Local files can be viewed directly — use extension for reliable type check
      const clickExt = (mediaItem.extension || mediaItem.fileName?.split('.').pop() || '').toLowerCase();
      const isClickVideo = ['mp4','avi','mov','wmv','flv','mkv','webm','m4v','mpg','mpeg','3gp','ogv','ts','mts'].includes(clickExt);
      if (isClickVideo) {
        setPlayingVideo(mediaItem);
      } else {
        setSelectedMedia(mediaItem);
      }
    }
  };

  const handleOpenInExplorer = async (path: string) => {
    try {
      await invoke('open_in_explorer', { path });
    } catch (error) {
      console.error('Failed to open in Explorer:', error);
      alert(`Failed to open file in Explorer: ${error}`);
    }
  };

  return (
    <div className="media-gallery-modal">
      <div className="media-gallery">
        <div className="gallery-header">
          <div className="header-title">
            <h1>🖼️ MEDIA EXPLORER</h1>
            <p>Visual review of all media files found on the system</p>
          </div>

          <div className="header-actions">
            <Button variant="secondary" size="sm" onClick={onClose}>
              ✕ Close
            </Button>
            <Button variant="secondary" size="sm" onClick={() => {
              // Investigators expect "Clear Cache" to drop in-memory thumbs
              // too, so a re-scan or re-open starts fresh. Wipe both
              // singleton maps AND local state, then forward to host.
              persistentVideoThumbCache.clear();
              persistentImageThumbCache.clear();
              persistentIosFullCache.clear();
              setVideoThumbnailMap(new Map());
              onClearCache();
            }}>
              🗑️ Clear Cache
            </Button>
          <Button variant="primary" size="sm" onClick={onStartScan} disabled={isScanning}>
            {isScanning ? 'Scanning...' : '🔄 New Scan'}
          </Button>
        </div>
      </div>

      {/* iOS AFC disclaimer banner — shown when iPhone media is present.
          AFC video thumbnails require streaming the full file off the
          device over USB, so users coming from the near-instant Windows
          / Android experience need to know up front that it's slow. */}
      {(() => {
        const iosVideosTotal = videos.filter(v => v.isIosAfcFile).length;
        if (iosVideosTotal === 0) return null;
        const iosVideosDone = videos.filter(
          v => v.isIosAfcFile && videoThumbnailMap.has(v.filePath)
        ).length;
        const allDone = iosVideosDone >= iosVideosTotal;
        return (
          <div
            className="ios-thumb-disclaimer"
            style={{
              background: allDone
                ? 'rgba(52, 168, 83, 0.10)'
                : 'rgba(255, 184, 0, 0.12)',
              border: `1px solid ${allDone ? 'rgba(52, 168, 83, 0.45)' : 'rgba(255, 184, 0, 0.40)'}`,
              borderRadius: 8,
              padding: '10px 14px',
              margin: '0 16px 12px',
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              fontSize: 13,
              color: 'var(--color-text-primary, #e6e6e6)',
            }}
          >
            <span style={{ fontSize: 18, lineHeight: 1 }}>
              {allDone ? '✅' : '⏳'}
            </span>
            <div style={{ flex: 1, lineHeight: 1.45 }}>
              {allDone ? (
                <>
                  <strong>iPhone video thumbnails complete</strong>
                  {' '}— {iosVideosDone} of {iosVideosTotal} generated.
                </>
              ) : (
                <>
                  <strong>
                    iPhone video thumbnails: {iosVideosDone} of {iosVideosTotal} generated
                  </strong>
                  {' '}— iOS recordings are streamed live over USB,
                  which is slower than local Windows / Android scans.
                  Large 4K videos can take 30–60 seconds each.
                  This is normal — you can continue browsing while they load.
                </>
              )}
            </div>
          </div>
        );
      })()}

      {/* Category Tabs */}
      <div className="category-tabs">
        <button
          className={`category-tab ${activeCategory === 'all' ? 'active' : ''}`}
          onClick={() => handleCategoryChange('all')}
        >
          <span className="tab-icon">📁</span>
          <span className="tab-label">All Media</span>
          <span className="tab-count">{media.length}</span>
        </button>
        <button
          className={`category-tab ${activeCategory === 'images' ? 'active' : ''}`}
          onClick={() => handleCategoryChange('images')}
        >
          <span className="tab-icon">🖼️</span>
          <span className="tab-label">Images</span>
          <span className="tab-count">{images.length}</span>
        </button>
        <button
          className={`category-tab ${activeCategory === 'videos' ? 'active' : ''}`}
          onClick={() => handleCategoryChange('videos')}
        >
          <span className="tab-icon">🎥</span>
          <span className="tab-label">Videos</span>
          <span className="tab-count">{videos.length}</span>
        </button>
        <button
          className={`category-tab flagged ${activeCategory === 'flagged' ? 'active' : ''}`}
          onClick={() => handleCategoryChange('flagged')}
        >
          <span className="tab-icon">🚨</span>
          <span className="tab-label">Flagged</span>
          <span className="tab-count">{flaggedMedia.length}</span>
        </button>
      </div>

      {/* Category Header with Count */}
      <div className="category-header">
        <div className="category-info">
          <h2>
            {activeCategory === 'all' && '📁 All Media Files'}
            {activeCategory === 'images' && '🖼️ Image Files'}
            {activeCategory === 'videos' && '🎥 Video Files'}
            {activeCategory === 'flagged' && '🚨 Flagged Media'}
          </h2>
          <p className="category-count">
            Showing {startIndex + 1}-{Math.min(endIndex, filteredMedia.length)} of {filteredMedia.length} file{filteredMedia.length !== 1 ? 's' : ''}
            {totalPages > 1 && <span> • Page {currentPage} of {totalPages}</span>}
            {criticalCount > 0 && activeCategory === 'flagged' && (
              <span className="critical-indicator"> • {criticalCount} critical</span>
            )}
          </p>
        </div>
      </div>

      {/* Gallery Grid */}
      <div className="gallery-content">
        {filteredMedia.length === 0 ? (
          <div className="empty-category">
            <div className="empty-icon">
              {activeCategory === 'images' && '🖼️'}
              {activeCategory === 'videos' && '🎥'}
              {activeCategory === 'flagged' && '✓'}
              {activeCategory === 'all' && '📁'}
            </div>
            <h3>No {activeCategory === 'all' ? 'media' : activeCategory} found</h3>
            <p>
              {activeCategory === 'flagged' 
                ? 'No flagged media files detected'
                : `No ${activeCategory} files found in this scan`
              }
            </p>
          </div>
        ) : (
          <>
            <div className="gallery-grid">
              {paginatedMedia.map(item => (
                <MediaThumbnail
                  key={item.id}
                  media={item}
                  onClick={() => handleMediaClick(item)}
                  pullMediaFile={pullMediaFile}
                  getCachedFile={getCachedFile}
                  preGeneratedThumbnail={videoThumbnailMap.get(item.filePath)}
                  onToggleFlag={onToggleFlag}
                  isFlagged={isFlagged}
                />
              ))}
            </div>

            {/* Pagination Controls */}
            {totalPages > 1 && (
              <div className="pagination-controls">
                <button 
                  className="pagination-button"
                  onClick={() => setCurrentPage(1)}
                  disabled={currentPage === 1}
                >
                  « First
                </button>
                <button 
                  className="pagination-button"
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                >
                  ‹ Previous
                </button>
                
                <div className="pagination-info">
                  Page <input 
                    type="number" 
                    min="1" 
                    max={totalPages}
                    value={currentPage}
                    onChange={(e) => {
                      const page = parseInt(e.target.value);
                      if (page >= 1 && page <= totalPages) {
                        setCurrentPage(page);
                      }
                    }}
                    className="page-input"
                  /> of {totalPages}
                </div>

                <button 
                  className="pagination-button"
                  onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                >
                  Next ›
                </button>
                <button 
                  className="pagination-button"
                  onClick={() => setCurrentPage(totalPages)}
                  disabled={currentPage === totalPages}
                >
                  Last »
                </button>
              </div>
            )}
          </>
        )}
      </div>

      {/* Image Detail Modal */}
      {selectedMedia && (
        <MediaDetailModal
          media={selectedMedia}
          onClose={() => setSelectedMedia(null)}
          onOpenInExplorer={handleOpenInExplorer}
          onToggleFlag={onToggleFlag}
          isFlagged={isFlagged}
        />
      )}

      {/* Video Player Modal */}
      {playingVideo && (
        <VideoPlayerModal
          media={playingVideo}
          onClose={() => setPlayingVideo(null)}
          onOpenInExplorer={handleOpenInExplorer}
          onToggleFlag={onToggleFlag}
          isFlagged={isFlagged}
        />
      )}
      </div>
    </div>
  );
};

// Media Thumbnail Component
const MediaThumbnail: React.FC<{
  media: MediaFile;
  onClick: () => void;
  pullMediaFile?: (media: MediaFile) => Promise<any>;
  getCachedFile?: (filePath: string) => any;
  preGeneratedThumbnail?: string;
  onToggleFlag?: (itemId: string) => void;
  isFlagged?: (itemId: string) => boolean;
}> = ({ media, onClick, pullMediaFile, getCachedFile, preGeneratedThumbnail, onToggleFlag, isFlagged }) => {
  const hasCriticalFlags = media.flags && Array.isArray(media.flags) && media.flags.some(f => f.severity === 'critical');
  const hasFlags = media.flags && Array.isArray(media.flags) && media.flags.length > 0;
  // User "Tag as Evidence" state — independent of scanner flags
  const itemId = `media-${media.filePath}`;
  const evidenceFlagged = isFlagged?.(itemId) || false;
  const handleEvidenceClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();
    onToggleFlag?.(itemId);
  };
  // Use extension for reliable type detection (mediaType from backend can be wrong)
  const ext = (media.extension || media.fileName?.split('.').pop() || '').toLowerCase();
  const VIDEO_EXT_SET = new Set(['mp4','avi','mov','wmv','flv','mkv','webm','m4v','mpg','mpeg','3gp','ogv','ts','mts']);
  const isVideo = VIDEO_EXT_SET.has(ext);
  const isAndroid = media.isAndroidFile;
  const isIosAfc = media.isIosAfcFile;
  // Seed from persistent cache (survives MediaGallery mount/unmount) before
  // falling back to backend-provided thumbnailPath or pre-generated.
  const [thumbnailPath, setThumbnailPath] = React.useState(
    persistentImageThumbCache.get(media.filePath)
      || media.thumbnailPath
      || preGeneratedThumbnail
      || null
  );
  const [isGenerating, setIsGenerating] = React.useState(false);
  const [videoThumbnail, setVideoThumbnail] = React.useState<string | null>(null);
  const thumbnailRef = React.useRef<HTMLDivElement>(null);
  const hasAttemptedGeneration = React.useRef(false);
  const retryCount = React.useRef(0);

  // Sync if backend thumbnail or pre-generated thumbnail arrives after mount
  React.useEffect(() => {
    if (!thumbnailPath) {
      if (media.thumbnailPath) {
        setThumbnailPath(media.thumbnailPath);
      } else if (preGeneratedThumbnail) {
        setThumbnailPath(preGeneratedThumbnail);
      }
    }
  }, [media.thumbnailPath, preGeneratedThumbnail]);

  // Function to generate thumbnail
  const generateThumbnail = React.useCallback(async () => {
    if (!isAndroid || thumbnailPath || !pullMediaFile || !getCachedFile || isGenerating) {
      return;
    }

    // Check if already cached
    const cached = getCachedFile(media.filePath);
    if (cached?.thumbnailPath) {
      setThumbnailPath(cached.thumbnailPath);
      hasAttemptedGeneration.current = true;
      return;
    }

    // Allow up to 2 attempts (first try + one retry)
    if (hasAttemptedGeneration.current && retryCount.current >= 1) {
      return;
    }

    hasAttemptedGeneration.current = true;

    // Pull file and generate thumbnail
    setIsGenerating(true);
    try {
      const result = await pullMediaFile(media);

      if (result?.thumbnailPath) {
        setThumbnailPath(result.thumbnailPath);
        persistentImageThumbCache.set(media.filePath, result.thumbnailPath);
      } else if (isVideo && result?.localPath) {
        // No backend thumbnail, generate in browser for videos
        const videoUrl = convertToMediaProtocol(result.localPath);
        const browserThumbnail = await getVideoThumbnail(videoUrl, 300);
        if (browserThumbnail) {
          setVideoThumbnail(browserThumbnail);
        }
      }
    } catch (error) {
      console.error('[MediaThumbnail] Failed to generate thumbnail:', media.fileName, error);
      // Allow retry on failure
      retryCount.current++;
      hasAttemptedGeneration.current = false;
    } finally {
      setIsGenerating(false);
    }
  }, [isAndroid, thumbnailPath, pullMediaFile, getCachedFile, media, isGenerating, isVideo]);

  // Auto-generate thumbnail for Android files when they come into view
  // For flagged items, generate immediately since they're high priority
  React.useEffect(() => {
    if (!isAndroid || thumbnailPath || !pullMediaFile || !getCachedFile) {
      return;
    }

    // Check if another code path (e.g. detail modal click) already cached this file
    const cached = getCachedFile(media.filePath);
    if (cached?.thumbnailPath) {
      setThumbnailPath(cached.thumbnailPath);
      return;
    }

    // For flagged media, generate thumbnail immediately (high priority)
    if (hasFlags && !hasAttemptedGeneration.current) {
      generateThumbnail();
      return;
    }

    // For non-flagged media, use IntersectionObserver for lazy loading
    const observer = new IntersectionObserver(
      async (entries) => {
        if (entries[0].isIntersecting && !isGenerating && !hasAttemptedGeneration.current) {
          generateThumbnail();
        }
      },
      { rootMargin: '200px' } // Start loading 200px before entering viewport
    );

    if (thumbnailRef.current) {
      observer.observe(thumbnailRef.current);
    }

    return () => observer.disconnect();
  }, [isAndroid, thumbnailPath, hasFlags, pullMediaFile, getCachedFile, generateThumbnail, isGenerating, media.filePath]);

  // ─── iOS AFC live-triage: lazy thumbnail via Python sidecar ──────────────
  // Per-item path handles IMAGES ONLY. AFC videos are handled exclusively
  // by the gallery-level sequential queue (see useEffect near line 152),
  // which has proper backoff/yield so it doesn't fight the walk hasher for
  // the single AFC connection. Without this gate both code paths fire
  // get_ios_afc_video_thumbnail for the same files, causing daemon-side
  // serialization and starving image thumbnails on the Flagged tab.
  React.useEffect(() => {
    if (!isIosAfc || thumbnailPath || !media.filePath || isVideo) {
      return;
    }

    let cancelled = false;
    const fetchAfcThumb = async () => {
      if (hasAttemptedGeneration.current) return;
      hasAttemptedGeneration.current = true;
      setIsGenerating(true);
      try {
        const r = await invoke<{ dataUrl: string }>('get_ios_afc_thumbnail', {
          udid: media.iosUdid || null,
          path: media.filePath,
          maxDim: 256,
        });
        // ALWAYS persist on success — even if this component was unmounted
        // mid-await. Otherwise React StrictMode / parent re-renders that
        // toggle `cancelled=true` between invoke and resolve cause us to
        // throw away the result, so the next mount fires another invoke and
        // the loop repeats forever. The next mount reads the cache via the
        // initial useState() seed.
        //
        // Also: drop the `!cancelled` guard on setThumbnailPath. Under
        // StrictMode the first effect's cleanup runs `cancelled=true` before
        // the in-flight fetch resolves; but the SECOND effect run skips
        // re-fetching because hasAttemptedGeneration is set, so without the
        // unconditional setState the component sits on `isGenerating=true`
        // forever. React drops state updates on truly-unmounted components
        // (with a dev warning), so this is safe.
        if (r?.dataUrl) {
          persistentImageThumbCache.set(media.filePath, r.dataUrl);
          setThumbnailPath(r.dataUrl);
        }
      } catch (err) {
        // Common: unsupported codec/format, file too large, transient AFC
        // error, ffmpeg fails on weird MOV layouts. Surface once.
        console.warn('[iOS AFC thumb]', media.fileName, err);
      } finally {
        if (!cancelled) setIsGenerating(false);
      }
    };

    // Flagged items: fetch immediately. Otherwise wait for viewport.
    if (hasFlags) {
      fetchAfcThumb();
    } else {
      const observer = new IntersectionObserver(
        (entries) => {
          if (entries[0].isIntersecting) {
            fetchAfcThumb();
            observer.disconnect();
          }
        },
        { rootMargin: '200px' }
      );
      if (thumbnailRef.current) observer.observe(thumbnailRef.current);
      return () => {
        cancelled = true;
        observer.disconnect();
      };
    }
    return () => {
      cancelled = true;
    };
  }, [isIosAfc, thumbnailPath, isVideo, media.filePath, media.iosUdid, media.fileName, hasFlags]);

  // No individual video thumbnail generation — handled by sequential queue at MediaGallery level

  return (
    <div
      ref={thumbnailRef}
      className={`media-thumbnail ${hasCriticalFlags ? 'critical' : ''} ${hasFlags ? 'flagged' : ''} ${evidenceFlagged ? 'evidence-flagged' : ''} ${isVideo ? 'video' : ''} ${isAndroid ? 'android' : ''}`}
      onClick={onClick}
      title={isAndroid ? 'Click to pull from device and view' : (isVideo ? 'Click to play video' : 'Click to view details')}
    >
      <div className="thumbnail-image-container">
        {/* Local videos: use <video> element — browser shows first frame automatically.
            Skip Android (no local path) and iOS AFC (asset protocol 403s; thumb arrives via
            daemon as a data URL in `thumbnailPath`). */}
        {isVideo && !isAndroid && !isIosAfc && media.filePath ? (
          <video
            src={convertToMediaProtocol(media.filePath) + '#t=0.1'}
            muted
            preload="metadata"
            className="thumbnail-image"
            style={{ width: '100%', height: '100%', objectFit: 'cover', pointerEvents: 'none' }}
          />
        ) : thumbnailPath && thumbnailPath.startsWith('data:') ? (
          <img 
            src={thumbnailPath} 
            alt={media.fileName}
            className="thumbnail-image"
            style={{ width: '100%', height: '100%', objectFit: 'cover' }}
          />
        ) : thumbnailPath ? (
          <LazyThumbnail
            src={thumbnailPath}
            alt={media.fileName}
            mediaType={isVideo ? 'video' : 'image'}
            className="thumbnail-image"
          />
        ) : videoThumbnail ? (
          <img 
            src={videoThumbnail} 
            alt={media.fileName}
            className="thumbnail-image"
            style={{ width: '100%', height: '100%', objectFit: 'cover' }}
          />
        ) : isGenerating ? (
          <div className="thumbnail-placeholder">
            <div className="loading-spinner-small"></div>
            <div className="generating-text">
              {isIosAfc ? 'Streaming…' : 'Generating...'}
            </div>
          </div>
        ) : isVideo ? (
          <div className="thumbnail-placeholder">
            <div className="video-icon">🎥</div>
            <div className="video-filename">{media.fileName}</div>
            {isAndroid && <div className="android-badge">📱 On Device</div>}
            {isIosAfc && <div className="android-badge">📱 On iPhone</div>}
          </div>
        ) : (
          <div className="thumbnail-placeholder">
            <div className="image-icon">🖼️</div>
            <div className="image-filename">{media.fileName}</div>
            {isAndroid && <div className="android-badge">📱 On Device</div>}
            {isIosAfc && <div className="android-badge">📱 On iPhone</div>}
          </div>
        )}

        {/* Video Play Overlay */}
        {isVideo && (
          <div className="video-play-overlay">
            <div className="play-button">
              <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
                <circle cx="24" cy="24" r="20" fill="rgba(0, 0, 0, 0.7)" stroke="white" strokeWidth="2"/>
                <path d="M19 16L32 24L19 32V16Z" fill="white"/>
              </svg>
            </div>
          </div>
        )}
      </div>

      {/* Flags Badge */}
      {hasFlags && (
        <div className="flag-badge">
          <span className="flag-icon">⚠️</span>
          <span className="flag-count">{media.flags?.length || 0}</span>
        </div>
      )}

      {hasCriticalFlags && (
        <div className="critical-badge">🚨 CRITICAL</div>
      )}

      {/* Evidence-flag toggle button (user "Tag as Evidence" — distinct from scanner flags) */}
      {onToggleFlag && (
        <button
          type="button"
          className={`evidence-flag-button ${evidenceFlagged ? 'is-flagged' : ''}`}
          onClick={handleEvidenceClick}
          onMouseDown={(e) => e.stopPropagation()}
          title={evidenceFlagged ? 'Tagged as Evidence — click to remove' : 'Tag as Evidence'}
          aria-label={evidenceFlagged ? 'Remove evidence tag' : 'Tag as evidence'}
        >
          <span className="evidence-flag-icon">{evidenceFlagged ? '🔖' : '🏷️'}</span>
          <span className="evidence-flag-label">
            {evidenceFlagged ? 'Tagged' : 'Tag'}
          </span>
        </button>
      )}

      {/* File Info */}
      <div className="thumbnail-info">
        <div className="thumbnail-type-icon">
          {isVideo ? '🎥' : '🖼️'}
        </div>
        <div className="thumbnail-details">
          <div className="thumbnail-name" title={media.fileName || media.filename}>
            {media.fileName || media.filename}
          </div>
          <div className="thumbnail-meta">
            <span className="thumbnail-size">{formatFileSize(media.fileSize || media.sizeBytes || 0)}</span>
            {media.width && media.height && (
              <>
                <span className="meta-separator">•</span>
                <span className="thumbnail-dimensions">{media.width}×{media.height}</span>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

// Media List Item Component
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const MediaListItem: React.FC<{
  media: MediaFile;
  isSelected: boolean;
  onClick: () => void;
}> = ({ media, isSelected, onClick }) => {
  const hasCriticalFlags = media.flags && Array.isArray(media.flags) && media.flags.some(f => f.severity === 'critical');

  return (
    <div
      className={`media-list-item ${isSelected ? 'selected' : ''} ${hasCriticalFlags ? 'critical' : ''}`}
      onClick={onClick}
    >
      <div className="list-item-thumbnail">
        {media.thumbnailPath ? (
          <img src={convertToMediaProtocol(media.thumbnailPath)} alt={media.fileName} />
        ) : (
          <span className="placeholder-icon">
            {media.mediaType === 'video' ? '🎥' : '🖼️'}
          </span>
        )}
      </div>

      <div className="list-item-info">
        <div className="list-item-name">{media.fileName}</div>
        <div className="list-item-path">{media.filePath}</div>
        <div className="list-item-media">
          <span>{formatFileSize(media.fileSize || media.sizeBytes || 0)}</span>
          <span>•</span>
          <span>{media.extension ? media.extension.toUpperCase() : (media.fileType || 'UNKNOWN')}</span>
          {media.dateModified && (
            <>
              <span>•</span>
              <span>{new Date(media.dateModified).toLocaleDateString()}</span>
            </>
          )}
        </div>
      </div>

      <div className="list-item-flags">
        {media.flags && Array.isArray(media.flags) && media.flags.map((flag, index) => (
          <div
            key={index}
            className="flag-chip"
            style={{ borderColor: getSeverityColor(flag.severity) }}
          >
            {flag.source}
          </div>
        ))}
      </div>
    </div>
  );
};

// Media Detail Modal (For Images)
const MediaDetailModal: React.FC<{
  media: MediaFile;
  onClose: () => void;
  onOpenInExplorer: (path: string) => void;
  onToggleFlag?: (itemId: string) => void;
  isFlagged?: (itemId: string) => boolean;
}> = ({ media, onClose, onOpenInExplorer, onToggleFlag, isFlagged }) => {
  const itemId = `media-${media.filePath}`;
  const flagged = isFlagged?.(itemId) || false;

  // For iOS AFC images, neither `thumbnailPath` nor `localCachePath` is
  // populated on the MediaFile object — the only thumbnail we have is the
  // small (256px) data URL the grid fetched via `get_ios_afc_thumbnail` and
  // stashed in `persistentImageThumbCache`. We:
  //   1) show that small thumb immediately (better than the placeholder),
  //   2) request a larger (1600px) preview from the daemon for the modal,
  //   3) cache the larger preview in `persistentIosFullCache`.
  // Falls through to the standard asset-protocol path for everything else.
  const isIosAfc = media.isIosAfcFile;
  const cachedSmall = isIosAfc
    ? persistentImageThumbCache.get(media.filePath) || null
    : null;
  const cachedFull = isIosAfc
    ? persistentIosFullCache.get(media.filePath) || null
    : null;

  const [iosPreview, setIosPreview] = React.useState<string | null>(
    cachedFull || cachedSmall
  );
  const [iosLoading, setIosLoading] = React.useState<boolean>(
    !!isIosAfc && !cachedFull
  );
  const [iosError, setIosError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!isIosAfc || cachedFull) return;
    let cancelled = false;
    (async () => {
      try {
        const r = await invoke<{ dataUrl: string }>('get_ios_afc_thumbnail', {
          udid: media.iosUdid || null,
          path: media.filePath,
          maxDim: 1600,
        });
        if (cancelled) return;
        if (r?.dataUrl) {
          persistentIosFullCache.set(media.filePath, r.dataUrl);
          setIosPreview(r.dataUrl);
        }
      } catch (err: any) {
        if (cancelled) return;
        console.warn('[MediaDetailModal] full preview failed:', media.fileName, err);
        setIosError(String(err?.message || err || 'preview failed'));
      } finally {
        if (!cancelled) setIosLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isIosAfc, cachedFull, media.filePath]);

  // Pick the best image source:
  // - iOS AFC: iosPreview (full → small → null)
  // - everything else: existing thumbnailPath / localCachePath
  const previewSrc = isIosAfc
    ? iosPreview
    : (media.thumbnailPath || media.localCachePath || null);

  return (
    <div className="media-modal-overlay" onClick={onClose}>
      <div className="media-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>Media Details</h2>
          <button className="close-button" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body">
          <div className="modal-preview">
            {previewSrc ? (
              <img src={convertToMediaProtocol(previewSrc)} alt={media.fileName} />
            ) : iosLoading ? (
              <div className="preview-placeholder">
                <div className="wt-spinner" />
                <p>Loading preview from iPhone…</p>
              </div>
            ) : (
              <div className="preview-placeholder">
                {media.mediaType === 'video' ? '🎥' : '🖼️'}
                {media.isAndroidFile && <p>File on Android device - click to pull</p>}
                {isIosAfc && (
                  <p>
                    {media.mediaType === 'video'
                      ? 'Video on iPhone — open the player to stream it'
                      : iosError
                        ? `Preview failed: ${iosError}`
                        : 'Thumbnail not available (unsupported format or stream error)'}
                  </p>
                )}
              </div>
            )}
          </div>

          <div className="modal-details">
            <div className="detail-section">
              <h3>File Information</h3>
              <div className="detail-grid">
                <div className="detail-item">
                  <label>File Name</label>
                  <div className="detail-value">{media.fileName || media.filename || 'N/A'}</div>
                </div>
                <div className="detail-item">
                  <label>File Path</label>
                  <div className="detail-value path">{media.filePath || media.path || 'N/A'}</div>
                </div>
                <div className="detail-item">
                  <label>File Size</label>
                  <div className="detail-value">{formatFileSize(media.fileSize || media.sizeBytes || 0)}</div>
                </div>
                <div className="detail-item">
                  <label>Type</label>
                  <div className="detail-value">
                    {media.extension ? media.extension.toUpperCase() : (media.fileType || 'UNKNOWN')}
                    {' '}({media.mediaType || 'unknown'})
                  </div>
                </div>
                {(media.dateModified || media.modifiedDate) && (
                  <div className="detail-item">
                    <label>Modified</label>
                    <div className="detail-value">
                      {media.dateModified ? new Date(media.dateModified).toLocaleString() : media.modifiedDate}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {(media.md5Hash || media.sha256Hash) && (
              <div className="detail-section">
                <h3>File Hashes</h3>
                <div className="detail-grid">
                  {media.md5Hash && (
                    <div className="detail-item">
                      <label>MD5</label>
                      <div className="detail-value mono">{media.md5Hash}</div>
                    </div>
                  )}
                  {media.sha256Hash && (
                    <div className="detail-item">
                      <label>SHA256</label>
                      <div className="detail-value mono">{media.sha256Hash}</div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {media.flags && Array.isArray(media.flags) && media.flags.length > 0 && (
              <div className="detail-section flags-section">
                <h3>🚨 Flags ({media.flags.length})</h3>
                <div className="flags-list">
                  {media.flags.map((flag, index) => (
                    <div
                      key={index}
                      className={`flag-item severity-${flag.severity}`}
                    >
                      <div className="flag-header">
                        <span className="flag-severity">{flag.severity ? flag.severity.toUpperCase() : 'UNKNOWN'}</span>
                        <span className="flag-source">{flag.source}</span>
                      </div>
                      <div className="flag-reason">{flag.reason}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <Button variant="secondary" onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={() => onOpenInExplorer(media.filePath)}>
            📁 Open in Explorer
          </Button>
          {onToggleFlag && (
            <Button 
              variant={flagged ? "primary" : "danger"}
              onClick={() => onToggleFlag(itemId)}
            >
              {flagged ? '✓ Tagged as Evidence' : '🔖 Tag as Evidence'}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};

// Video Player Modal
const VideoPlayerModal: React.FC<{
  media: MediaFile;
  onClose: () => void;
  onOpenInExplorer: (path: string) => void;
  onToggleFlag?: (itemId: string) => void;
  isFlagged?: (itemId: string) => boolean;
}> = ({ media, onClose, onOpenInExplorer, onToggleFlag, isFlagged }) => {
  // Use local cache path if available (for Android files), otherwise use original path
  const mediaPath = media.localCachePath || media.filePath || media.path || '';
  const itemId = `media-${media.filePath}`; // Use original path for ID
  const flagged = isFlagged?.(itemId) || false;
  const videoRef = useRef<HTMLVideoElement>(null);
  const [videoError, setVideoError] = React.useState<string | null>(null);
  const [isLoading, setIsLoading] = React.useState(true);
  const [videoSrc, setVideoSrc] = React.useState<string>('');
  
  // Load video source using the best method
  useEffect(() => {
    const loadVideoSource = async () => {
      try {
        setIsLoading(true);
        setVideoError(null);

        // iOS AFC live-triage: hand the <video> element a URL pointed
        // at our registered `scout-afc` URI scheme. On Windows/Tauri 2
        // that resolves to http://scout-afc.localhost/<encoded-path>,
        // which the Rust handler proxies through AFC byte-ranges.
        // No file copy to disk — the element issues HTTP Range
        // requests as it buffers.
        if (media.isIosAfcFile) {
          const afcPath = media.filePath || '';
          if (!afcPath) {
            setVideoError('iOS AFC video has no path');
            setIsLoading(false);
            return;
          }
          // convertFileSrc handles platform differences and encodes the
          // path. The Rust handler strips any duplicate leading slashes
          // introduced by the percent-encoding round-trip.
          const url = convertFileSrc(afcPath, 'scout-afc');
          console.log('[Video] iOS AFC src:', url);
          setVideoSrc(url);
          return;
        }
        
        // Debug logging with explicit string conversion
        console.log('Video player preparing:', {
          'media.localCachePath': String(media.localCachePath),
          'media.filePath': String(media.filePath),
          'computed mediaPath': String(mediaPath),
          'mediaPath type': typeof mediaPath,
          'mediaPath is string': typeof mediaPath === 'string',
          'mediaPath length': mediaPath ? mediaPath.length : 0
        });
        
        // Safety check
        if (!mediaPath || typeof mediaPath !== 'string' || mediaPath.trim() === '') {
          console.error('Invalid mediaPath:', mediaPath, 'type:', typeof mediaPath);
          setVideoError('Invalid media path - file not found');
          setIsLoading(false);
          return;
        }
        
        // Use custom media protocol for better compatibility
        const src = convertToMediaProtocol(mediaPath);
        
        console.log('Video player converted:', {
          usedPath: mediaPath,
          convertedSrc: src,
          srcLength: src.length,
          fileName: media.fileName || media.filename
        });
        
        if (!src || src.trim() === '') {
          console.error('Failed to convert path to media protocol');
          setVideoError('Failed to generate media URL');
          setIsLoading(false);
          return;
        }
        
        setVideoSrc(src);
      } catch (error) {
        console.error('Failed to load video source:', error);
        setVideoError('Failed to prepare video for playback');
        setIsLoading(false);
      }
    };
    
    loadVideoSource();
  }, [mediaPath, media.filePath, media.localCachePath, media.fileName, media.filename, media.isAndroidFile, media]);

  const handleVideoError = (e: React.SyntheticEvent<HTMLVideoElement, Event>) => {
    console.error('Video playback error:', e);
    const videoElement = e.currentTarget;
    const error = videoElement.error;
    
    // Check file extension
    const fileExt = (media.fileName || '').toLowerCase().split('.').pop();
    const unsupportedFormats = ['ts', 'mts', 'm2ts', 'avi', 'wmv', 'flv', 'mkv'];
    
    let errorMessage = 'Unknown error';
    if (error) {
      switch (error.code) {
        case error.MEDIA_ERR_ABORTED:
          errorMessage = 'Video playback was aborted';
          break;
        case error.MEDIA_ERR_NETWORK:
          errorMessage = 'Network error while loading video';
          break;
        case error.MEDIA_ERR_DECODE:
          errorMessage = unsupportedFormats.includes(fileExt || '') 
            ? `${fileExt?.toUpperCase()} format not supported by browser`
            : 'Video codec not supported or file is corrupted';
          break;
        case error.MEDIA_ERR_SRC_NOT_SUPPORTED:
          errorMessage = unsupportedFormats.includes(fileExt || '')
            ? `${fileExt?.toUpperCase()} format not supported by browser`
            : 'Video format not supported by browser';
          break;
      }
    }
    
    setVideoError(errorMessage);
    setIsLoading(false);
  };

  const handleVideoLoaded = () => {
    console.log('Video loaded successfully');
    setIsLoading(false);
    setVideoError(null);
  };

  return (
    <div className="media-modal-overlay video-modal" onClick={onClose}>
      <div className="media-modal video-player-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="header-left">
            <h2>🎥 Video Player</h2>
            <span className="video-filename">{media.fileName}</span>
          </div>
          <button className="close-button" onClick={onClose}>✕</button>
        </div>

        <div className="modal-body video-body">
          <div className="video-main-content">
            <div className="video-player-container">
              {isLoading && !videoError && (
                <div className="video-loading">
                  <div className="loading-spinner"></div>
                  <p>Loading video...</p>
                </div>
              )}
              {videoError && (
                <div className="video-error">
                  <p className="error-message">❌ {videoError}</p>
                  <p className="error-hint">
                    {media.isIosAfcFile
                      ? 'iOS AFC streaming failed. The codec may not be supported, the AFC connection may have dropped, or the file is too large to range-request. Try unplugging and reconnecting the iPhone.'
                      : media.isAndroidFile && media.localCachePath
                      ? 'File pulled from device. Open with VLC or Windows Media Player for playback.'
                      : 'Try opening the file directly in a media player like VLC'}
                  </p>
                  {!media.isIosAfcFile && (
                    <button
                      className="open-external-button"
                      onClick={() => onOpenInExplorer(media.localCachePath || mediaPath)}
                    >
                      📂 Open File Location
                    </button>
                  )}
                </div>
              )}
              <video
                ref={videoRef}
                src={videoSrc}
                controls
                autoPlay
                className="video-player"
                onError={handleVideoError}
                onLoadedData={handleVideoLoaded}
                onCanPlay={() => setIsLoading(false)}
                style={{ display: videoError ? 'none' : 'block' }}
              >
                Your browser does not support the video tag.
              </video>
            </div>

            <div className="video-metadata-panel">
              <div className="metadata-scroll">
                <div className="detail-section">
                  <h3>📄 File Information</h3>
                  <div className="detail-list">
                    <div className="detail-row">
                      <span className="detail-label">File Name:</span>
                      <span className="detail-text">{media.fileName || media.filename}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">File Path:</span>
                      <span 
                        className="detail-text path clickable" 
                        onClick={() => onOpenInExplorer(mediaPath)}
                        title="Click to open file location in Explorer"
                        style={{ cursor: 'pointer', textDecoration: 'underline' }}
                      >
                        {mediaPath}
                      </span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">File Size:</span>
                      <span className="detail-text">{formatFileSize(media.fileSize || media.sizeBytes || 0)}</span>
                    </div>
                    <div className="detail-row">
                      <span className="detail-label">Type:</span>
                      <span className="detail-text">
                        {media.extension ? media.extension.toUpperCase() : (media.fileType || 'UNKNOWN')}
                      </span>
                    </div>
                    {media.width && media.height && (
                      <div className="detail-row">
                        <span className="detail-label">Resolution:</span>
                        <span className="detail-text">{media.width} × {media.height}</span>
                      </div>
                    )}
                    {media.dateModified && (
                      <div className="detail-row">
                        <span className="detail-label">Modified:</span>
                        <span className="detail-text">{new Date(media.dateModified).toLocaleString()}</span>
                      </div>
                    )}
                  </div>
                </div>

                {media.flags && Array.isArray(media.flags) && media.flags.length > 0 && (
                  <div className="detail-section flags-section">
                    <h3>🚨 Flags ({media.flags.length})</h3>
                    <div className="flags-list">
                      {media.flags.map((flag, index) => (
                        <div
                          key={index}
                          className={`flag-item severity-${flag.severity}`}
                        >
                          <div className="flag-header">
                            <span className="flag-severity">{flag.severity ? flag.severity.toUpperCase() : 'UNKNOWN'}</span>
                            <span className="flag-source">{flag.source}</span>
                          </div>
                          <div className="flag-reason">{flag.reason}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="modal-footer">
          <Button variant="secondary" onClick={onClose}>Close</Button>
          <Button variant="primary" onClick={() => onOpenInExplorer(media.filePath)}>
            📁 Open in Explorer
          </Button>
          {onToggleFlag && (
            <Button 
              variant={flagged ? "primary" : "danger"}
              onClick={() => onToggleFlag(itemId)}
            >
              {flagged ? '✓ Tagged as Evidence' : '🔖 Tag as Evidence'}
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'var(--color-danger)';
    case 'high': return 'var(--color-accent-amber)';
    case 'medium': return 'var(--color-info)';
    case 'low': return 'var(--color-success)';
    default: return 'var(--color-text-muted)';
  }
}
