import React, { useState, useEffect, useRef } from 'react';
import { loadThumbnail } from '../utils/thumbnailLoader';
import './LazyThumbnail.css';

interface LazyThumbnailProps {
  /** Cached thumbnail path (may be empty/stale — the loader will self-heal). */
  src: string;
  /** Original media file, so a missing thumbnail can be regenerated. */
  sourcePath?: string;
  alt: string;
  mediaType: 'image' | 'video';
  className?: string;
  onError?: () => void;
}

/**
 * Lazy-loading thumbnail. Loads only when near the viewport, resolves the
 * image through the batching/self-healing thumbnail loader (base64 data URLs),
 * shows a spinner while pending, and a clear "No preview" state if the tile
 * genuinely can't be rendered (e.g. corrupt image or source no longer present).
 */
export const LazyThumbnail: React.FC<LazyThumbnailProps> = ({
  src,
  sourcePath,
  alt,
  mediaType,
  className = '',
  onError,
}) => {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isInView, setIsInView] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [imageSrc, setImageSrc] = useState<string>('');
  const imgRef = useRef<HTMLDivElement>(null);

  // Intersection Observer — flip to in-view shortly before entering viewport.
  useEffect(() => {
    if (!imgRef.current) return;
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setIsInView(true);
            observer.disconnect();
          }
        });
      },
      { rootMargin: '150px', threshold: 0.01 }
    );
    observer.observe(imgRef.current);
    return () => observer.disconnect();
  }, []);

  // Resolve the image once in view.
  useEffect(() => {
    if (!isInView) return;

    // Direct data/blob URLs (e.g. iOS AFC daemon thumbnails) need no loader.
    if (src && (src.startsWith('data:') || src.startsWith('blob:'))) {
      setImageSrc(src);
      return;
    }

    const key = sourcePath || src;
    if (!key) {
      // Nothing to load from — surface the no-preview state, don't spin.
      setHasError(true);
      onError?.();
      return;
    }

    let cancelled = false;
    setHasError(false);
    loadThumbnail({
      key,
      thumbPath: src || undefined,
      sourcePath: sourcePath || undefined,
      mediaType,
    })
      .then((dataUrl) => {
        if (cancelled) return;
        if (dataUrl) {
          setImageSrc(dataUrl);
        } else {
          setHasError(true);
          onError?.();
        }
      })
      .catch(() => {
        if (!cancelled) {
          setHasError(true);
          onError?.();
        }
      });

    return () => {
      cancelled = true;
    };
  }, [isInView, src, sourcePath, mediaType]);

  const handleLoad = () => setIsLoaded(true);

  const handleError = () => {
    setHasError(true);
    onError?.();
  };

  return (
    <div
      ref={imgRef}
      className={`lazy-thumbnail ${className} ${isLoaded ? 'loaded' : ''} ${hasError ? 'error' : ''}`}
    >
      {!isInView && (
        <div className="thumbnail-placeholder">
          <div className="placeholder-icon">
            {mediaType === 'video' ? '🎥' : '🖼️'}
          </div>
        </div>
      )}

      {isInView && !hasError && (
        <>
          {!isLoaded && (
            <div className="thumbnail-loading">
              <div className="loading-spinner-small"></div>
            </div>
          )}
          <img
            src={imageSrc || undefined}
            alt={alt}
            onLoad={handleLoad}
            onError={handleError}
            style={{ opacity: isLoaded ? 1 : 0 }}
          />
        </>
      )}

      {hasError && (
        <div className="thumbnail-error-state">
          <span className="error-icon">{mediaType === 'video' ? '🎥' : '🖼️'}</span>
          <span className="error-text">No preview</span>
        </div>
      )}
    </div>
  );
};
