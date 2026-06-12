// LocationMapView — Leaflet map for Location History items.
//
// Replaces the standard ItemList for the `location` section so investigators
// can see lat/long pins instead of raw coordinate strings.  Items must have
// `rawFields.latitude` and `rawFields.longitude` as numeric strings.
//
// Two exports:
//   • <LocationMapView />          — full-pane map, used in the center
//                                    when sectionFilter === "location".
//   • <LocationOverviewMap />      — compact preview for the case overview
//                                    page; reuses the same parsing helpers.
//
// Both use the dark CartoDB tile layer to match the admin dashboard.

import L from "leaflet";
import "leaflet/dist/leaflet.css";
import React, { useEffect, useMemo, useRef } from "react";
import {
  CircleMarker,
  MapContainer,
  Popup,
  TileLayer,
  useMap,
} from "react-leaflet";
import type { Bucket, WarrantItem } from "./WarrantTriageView";

interface MapPoint {
  id: string;
  lat: number;
  lng: number;
  item: WarrantItem;
}

function parsePoints(items: WarrantItem[]): MapPoint[] {
  const out: MapPoint[] = [];
  for (const it of items) {
    const raw = (it.rawFields || {}) as Record<string, unknown>;
    const lat = parseFloat(String(raw.latitude ?? ""));
    const lng = parseFloat(String(raw.longitude ?? ""));
    if (Number.isFinite(lat) && Number.isFinite(lng)) {
      out.push({ id: it.id, lat, lng, item: it });
    }
  }
  return out;
}

// FitBounds — child component that re-fits the map when point set changes.
const FitBounds: React.FC<{ points: MapPoint[] }> = ({ points }) => {
  const map = useMap();
  useEffect(() => {
    if (points.length === 0) return;
    const bounds = L.latLngBounds(points.map((p) => [p.lat, p.lng]));
    map.fitBounds(bounds, { padding: [40, 40], maxZoom: 12 });
  }, [points, map]);
  return null;
};

// PanToSelected — centers the map on the currently-selected item so the
// right-panel detail view always corresponds to a visible marker.
const PanToSelected: React.FC<{
  points: MapPoint[];
  selectedId: string | null;
}> = ({ points, selectedId }) => {
  const map = useMap();
  useEffect(() => {
    if (!selectedId) return;
    const p = points.find((pt) => pt.id === selectedId);
    if (!p) return;
    map.panTo([p.lat, p.lng], { animate: true });
  }, [selectedId, points, map]);
  return null;
};

interface LocationMapViewProps {
  items: WarrantItem[];
  buckets: Bucket[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

export const LocationMapView: React.FC<LocationMapViewProps> = ({
  items,
  buckets,
  selectedId,
  onSelect,
}) => {
  const points = useMemo(() => parsePoints(items), [items]);
  const bucketsById = useMemo(() => {
    const m: Record<string, Bucket> = {};
    for (const b of buckets) m[b.id] = b;
    return m;
  }, [buckets]);

  if (points.length === 0) {
    return (
      <div className="wt-empty">
        No mappable coordinates in this section.
      </div>
    );
  }

  return (
    <div className="wt-map-container">
      <MapContainer
        center={[points[0].lat, points[0].lng]}
        zoom={4}
        style={{ width: "100%", height: "100%" }}
        scrollWheelZoom
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/attributions">CARTO</a>'
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          subdomains="abcd"
        />
        <FitBounds points={points} />
        <PanToSelected points={points} selectedId={selectedId} />
        {points.map((p) => {
          const selected = p.id === selectedId;
          const flagged = p.item.isFlagged;
          const bucket = p.item.bucket ? bucketsById[p.item.bucket] : null;
          const fill = selected
            ? "#5DCFFF"
            : flagged
              ? "#FF5577"
              : bucket
                ? bucket.color
                : "#4A7AFF";
          return (
            <CircleMarker
              key={p.id}
              center={[p.lat, p.lng]}
              radius={selected ? 10 : 7}
              pathOptions={{
                color: "#0a0d18",
                weight: 1.5,
                fillColor: fill,
                fillOpacity: 0.9,
              }}
              eventHandlers={{
                click: () => onSelect(p.id),
              }}
            >
              <Popup>
                <div className="wt-map-popup">
                  <div className="wt-map-popup-coords">
                    {p.lat.toFixed(4)}, {p.lng.toFixed(4)}
                  </div>
                  {p.item.timestamp && (
                    <div className="wt-map-popup-ts">{p.item.timestamp}</div>
                  )}
                  {p.item.summary && (
                    <div className="wt-map-popup-summary">{p.item.summary}</div>
                  )}
                  <button
                    type="button"
                    className="wt-map-popup-btn"
                    onClick={() => onSelect(p.id)}
                  >
                    Open details →
                  </button>
                </div>
              </Popup>
            </CircleMarker>
          );
        })}
      </MapContainer>
      <div className="wt-map-legend">
        <span className="wt-map-legend-count">{points.length} locations</span>
      </div>
    </div>
  );
};

// ─── LocationOverviewMap — compact preview for the case overview card ───

interface LocationOverviewMapProps {
  items: WarrantItem[];
  onOpenAll: () => void;
}

export const LocationOverviewMap: React.FC<LocationOverviewMapProps> = ({
  items,
  onOpenAll,
}) => {
  const points = useMemo(() => parsePoints(items), [items]);
  const containerRef = useRef<HTMLDivElement | null>(null);

  if (points.length === 0) return null;

  return (
    <div className="wt-card wt-overview-map-card">
      <div className="wt-card-header">
        <span className="wt-card-title">📍 Locations</span>
        <button
          type="button"
          className="wt-card-link"
          onClick={onOpenAll}
        >
          View all {points.length} →
        </button>
      </div>
      <div className="wt-overview-map" ref={containerRef}>
        <MapContainer
          center={[points[0].lat, points[0].lng]}
          zoom={3}
          style={{ width: "100%", height: "100%" }}
          scrollWheelZoom={false}
          dragging={false}
          doubleClickZoom={false}
          zoomControl={false}
          attributionControl={false}
        >
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            subdomains="abcd"
          />
          <FitBounds points={points} />
          {points.map((p) => (
            <CircleMarker
              key={p.id}
              center={[p.lat, p.lng]}
              radius={4}
              pathOptions={{
                color: "#0a0d18",
                weight: 1,
                fillColor: "#4A7AFF",
                fillOpacity: 0.9,
              }}
            />
          ))}
        </MapContainer>
      </div>
    </div>
  );
};
