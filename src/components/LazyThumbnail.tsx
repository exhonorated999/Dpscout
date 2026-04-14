import React, { useState, useEffect, useRef } from 'react';
import { convertToMediaProtocol } from '../utils/mediaProtocol';
import './LazyThumbnail.css';

interface LazyThumbnailProps {
  src: string;
  alt: string;
  mediaType: 'image' | 'video';
  className?: string;
  onError?: () => void;
}

/**
 * Lazy-loading thumbnail component with intersection observer
 * Only loads images when they're about to enter the viewport
 */
export const LazyThumbnail: React.FC<LazyThumbnailProps> = ({
  src,
  alt,
  mediaType,
  className = '',
  onError
}) => {
  const [isLoaded, setIsLoaded] = useState(false);
  const [isInView, setIsInView] = useState(false);
  const [hasError, setHasError] = useState(false);
  const [imageSrc, setImageSrc] = useState<string>('');
  const imgRef = useRef<HTMLDivElement>(null);

  // Intersection Observer for lazy loading
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
      {
        rootMargin: '50px', // Start loading 50px before entering viewport
        threshold: 0.01
      }
    );

    observer.observe(imgRef.current);

    return () => observer.disconnect();
  }, []);

  // Load image source when in view
  useEffect(() => {
    if (isInView && src) {
      // Data URLs and blob URLs don't need protocol conversion
      if (src.startsWith('data:') || src.startsWith('blob:')) {
        setImageSrc(src);
      } else {
        const mediaUrl = convertToMediaProtocol(src);
        setImageSrc(mediaUrl);
      }
    }
  }, [isInView, src]);

  const handleLoad = () => {
    setIsLoaded(true);
  };

  const handleError = () => {
    console.error('Failed to load thumbnail:', src);
    setHasError(true);
    if (onError) onError();
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
          <span className="error-icon">⚠️</span>
          <span className="error-text">Load failed</span>
        </div>
      )}
    </div>
  );
};

/**
 * Preload thumbnails in batches for smoother scrolling
 */
export const preloadThumbnails = async (thumbnailPaths: string[], batchSize: number = 10) => {
  const batches = [];
  for (let i = 0; i < thumbnailPaths.length; i += batchSize) {
    batches.push(thumbnailPaths.slice(i, i + batchSize));
  }

  for (const batch of batches) {
    await Promise.all(
      batch.map(path => {
        return new Promise((resolve) => {
          const img = new Image();
          img.onload = resolve;
          img.onerror = resolve; // Continue even if one fails
          img.src = convertToMediaProtocol(path);
        });
      })
    );
  }
};
