import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { ThreatGraphResponse, ThreatNode } from '../../types';
import { WebGLFallback } from '../common/WebGLFallback';
import { Search, Filter, ShieldAlert, CheckCircle2, AlertTriangle, X } from 'lucide-react';

interface ThreatNetwork3DProps {
  graphData: ThreatGraphResponse | null;
  onSelectNode?: (node: ThreatNode) => void;
}

export const ThreatNetwork3D: React.FC<ThreatNetwork3DProps> = ({ graphData, onSelectNode }) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [hasWebGL, setHasWebGL] = useState(true);
  const [selectedNode, setSelectedNode] = useState<ThreatNode | null>(null);
  const [searchFilter, setSearchFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    try {
      const testCanvas = document.createElement('canvas');
      const gl = testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl');
      if (!gl) {
        setHasWebGL(false);
        return;
      }
    } catch {
      setHasWebGL(false);
      return;
    }

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 550;

    // 1. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(50, width / height, 0.1, 1000);
    camera.position.set(0, 0, 16);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    // 2. Lighting
    const ambient = new THREE.AmbientLight(0xf5f3ec, 2.0);
    scene.add(ambient);

    const dirLight = new THREE.DirectionalLight(0xffffff, 1.8);
    dirLight.position.set(10, 15, 10);
    scene.add(dirLight);

    // 3. Prepare Node Mesh and Link Objects
    const rootGroup = new THREE.Group();
    scene.add(rootGroup);

    // Generate fallback nodes if graph data is empty
    const rawNodes = (graphData && graphData.nodes.length > 0) ? graphData.nodes : [
      { id: 'c1', name: 'Ladki Bahin Campaign Cluster', type: 'campaign', size: 18, color: '#B8794B', status: 'active', risk_score: 90 },
      { id: 'i1', name: 'ladkibahin-portal-free.xyz', type: 'indicator', indicator_type: 'domain', severity: 'critical', review_state: 'reviewed', confidence: 95, size: 13, color: '#C0392B', occurrence_count: 8 },
      { id: 'i2', name: 'ladakibahin.maharashtra.gov.in', type: 'indicator', indicator_type: 'domain', severity: 'low', review_state: 'reviewed', confidence: 100, size: 14, color: '#477C78', occurrence_count: 24 },
      { id: 'i3', name: 'com.scheme.ladkibahin (Trojan APK)', type: 'indicator', indicator_type: 'apk_sha256', severity: 'critical', review_state: 'reviewed', confidence: 99, size: 12, color: '#C0392B', occurrence_count: 5 },
      { id: 'i4', name: 'msedcl-light-bill-update.top', type: 'indicator', indicator_type: 'domain', severity: 'high', review_state: 'reviewed', confidence: 90, size: 12, color: '#D35400', occurrence_count: 4 },
      { id: 'i5', name: 'mahadiscom.in', type: 'indicator', indicator_type: 'domain', severity: 'low', review_state: 'reviewed', confidence: 100, size: 14, color: '#477C78', occurrence_count: 52 },
      { id: 'i6', name: 'urgent-bill-notice.cc', type: 'indicator', indicator_type: 'domain', severity: 'unreviewed', review_state: 'unreviewed', confidence: 45, size: 10, color: '#738087', occurrence_count: 2 },
      { id: 'c2', name: 'MSEDCL Urgency Scam Cluster', type: 'campaign', size: 16, color: '#B8794B', status: 'active', risk_score: 85 },
      { id: 'k1', name: 'CASE-MSG-20261031-825F1945', type: 'case', size: 10, color: '#477C78', risk_score: 75 },
      { id: 'k2', name: 'CASE-APK-20261031-9CF8C43F', type: 'case', size: 10, color: '#477C78', risk_score: 95 },
    ];

    // Filter nodes according to search & category
    const activeNodes = rawNodes.filter((n) => {
      const matchCat = categoryFilter === 'ALL' || n.type === categoryFilter.toLowerCase();
      const matchSearch = !searchFilter || n.name.toLowerCase().includes(searchFilter.toLowerCase());
      return matchCat && matchSearch;
    });

    const nodeMeshes: { mesh: THREE.Mesh; data: ThreatNode }[] = [];
    const nodeRadius = 5.5;

    // Distribute nodes in a 3D spherical constellation
    activeNodes.forEach((n, idx) => {
      const phi = Math.acos(-1 + (2 * idx) / activeNodes.length);
      const theta = Math.sqrt(activeNodes.length * Math.PI) * phi;
      const nAny = n as any;

      const x = (nAny.x !== undefined ? nAny.x : nodeRadius * Math.cos(theta) * Math.sin(phi));
      const y = (nAny.y !== undefined ? nAny.y : nodeRadius * Math.sin(theta) * Math.sin(phi));
      const z = (nAny.z !== undefined ? nAny.z : nodeRadius * Math.cos(phi));

      const sphereGeo = new THREE.SphereGeometry(n.size * 0.035, 24, 24);
      const sphereMat = new THREE.MeshStandardMaterial({
        color: new THREE.Color(n.color),
        roughness: 0.25,
        metalness: 0.3,
        emissive: new THREE.Color(n.color),
        emissiveIntensity: n.color === '#C0392B' ? 0.35 : 0.15,
      });

      const mesh = new THREE.Mesh(sphereGeo, sphereMat);
      mesh.position.set(x, y, z);
      rootGroup.add(mesh);
      nodeMeshes.push({ mesh, data: n as ThreatNode });

      // Add a translucent halo glow ring around high severity nodes
      if (n.severity === 'critical') {
        const haloGeo = new THREE.RingGeometry(n.size * 0.045, n.size * 0.055, 32);
        const haloMat = new THREE.MeshBasicMaterial({
          color: 0xc0392b,
          side: THREE.DoubleSide,
          transparent: true,
          opacity: 0.45,
        });
        const haloMesh = new THREE.Mesh(haloGeo, haloMat);
        mesh.add(haloMesh);
      }
    });

    // 4. Interconnecting Lines
    const lineMat = new THREE.LineBasicMaterial({
      color: 0xdddcd3,
      transparent: true,
      opacity: 0.35,
    });

    for (let i = 0; i < nodeMeshes.length; i++) {
      for (let j = i + 1; j < nodeMeshes.length; j++) {
        const d = nodeMeshes[i].mesh.position.distanceTo(nodeMeshes[j].mesh.position);
        if (d < 4.8) {
          const points = [nodeMeshes[i].mesh.position, nodeMeshes[j].mesh.position];
          const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
          const line = new THREE.Line(lineGeo, lineMat);
          rootGroup.add(line);
        }
      }
    }

    // 5. Orbit Controls & Raycasting for Click Selection
    const raycaster = new THREE.Raycaster();
    const mouse = new THREE.Vector2();
    let isDragging = false;
    let prevX = 0;
    let prevY = 0;

    const onPointerDown = (e: PointerEvent) => {
      isDragging = true;
      prevX = e.clientX;
      prevY = e.clientY;
    };

    const onPointerMove = (e: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouse.y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);

      if (isDragging) {
        const deltaX = e.clientX - prevX;
        const deltaY = e.clientY - prevY;
        rootGroup.rotation.y += deltaX * 0.006;
        rootGroup.rotation.x += deltaY * 0.006;
        prevX = e.clientX;
        prevY = e.clientY;
      }
    };

    const onPointerUp = (e: PointerEvent) => {
      isDragging = false;
      const rect = container.getBoundingClientRect();
      const clickX = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const clickY = -(((e.clientY - rect.top) / rect.height) * 2 - 1);

      raycaster.setFromCamera(new THREE.Vector2(clickX, clickY), camera);
      const intersects = raycaster.intersectObjects(nodeMeshes.map((nm) => nm.mesh));

      if (intersects.length > 0) {
        const hit = nodeMeshes.find((nm) => nm.mesh === intersects[0].object);
        if (hit) {
          setSelectedNode(hit.data);
          if (onSelectNode) onSelectNode(hit.data);
        }
      }
    };

    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      camera.position.z = THREE.MathUtils.clamp(camera.position.z + e.deltaY * 0.01, 8, 26);
    };

    container.addEventListener('pointerdown', onPointerDown);
    container.addEventListener('pointermove', onPointerMove);
    container.addEventListener('pointerup', onPointerUp);
    container.addEventListener('wheel', onWheel, { passive: false });

    // 6. Animation Loop
    let animId: number;
    const animate = () => {
      animId = requestAnimationFrame(animate);
      if (!isDragging) {
        rootGroup.rotation.y += 0.0018;
      }
      renderer.render(scene, camera);
    };
    animate();

    // 7. Resize Handler
    const handleResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animId);
      container.removeEventListener('pointerdown', onPointerDown);
      container.removeEventListener('pointermove', onPointerMove);
      container.removeEventListener('pointerup', onPointerUp);
      container.removeEventListener('wheel', onWheel);
      window.removeEventListener('resize', handleResize);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, [graphData, categoryFilter, searchFilter, onSelectNode]);

  if (!hasWebGL) {
    return <WebGLFallback title="3D Threat Intelligence Network (2D Compatibility Mode)" />;
  }

  return (
    <div className="relative w-full h-[580px] rounded-3xl overflow-hidden liquid-glass-elevated border border-[#DDDCD3]">
      {/* Top Controls Toolbar */}
      <div className="absolute top-4 left-4 right-4 z-20 flex flex-wrap items-center justify-between gap-3 pointer-events-auto">
        {/* Search */}
        <div className="flex items-center gap-2 liquid-glass px-3 py-1.5 rounded-full border border-white/80 shadow-sm w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-[#738087]" />
          <input
            type="text"
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
            placeholder="Search threat nodes & domains..."
            className="bg-transparent border-none text-xs text-[#202C32] focus:outline-none w-full"
          />
        </div>

        {/* Filter Pills */}
        <div className="flex items-center gap-1.5 overflow-x-auto">
          {['ALL', 'CAMPAIGN', 'INDICATOR', 'CASE'].map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`px-3 py-1 text-[11px] font-medium rounded-full transition cursor-pointer ${
                categoryFilter === cat
                  ? 'bg-[#477C78] text-white shadow-sm'
                  : 'liquid-glass text-[#738087] hover:text-[#202C32]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* 3D WebGL Canvas Container */}
      <div ref={mountRef} className="w-full h-full cursor-grab active:cursor-grabbing select-none" />

      {/* Legend Ribbon */}
      <div className="absolute bottom-4 left-4 z-20 hidden md:flex items-center gap-4 liquid-glass px-4 py-2 rounded-2xl text-[11px] text-[#738087]">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#C0392B]" />
          <span>Confirmed Malicious</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#D35400]" />
          <span>Suspicious Reviewed</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#738087]" />
          <span>Unreviewed / Candidate</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#477C78]" />
          <span>Official Scheme Anchor</span>
        </div>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedNode && (
        <div className="absolute top-16 right-4 z-30 w-80 max-w-[90vw] liquid-glass-elevated p-5 rounded-2xl shadow-xl animate-in fade-in slide-in-from-right-4 duration-200">
          <div className="flex items-start justify-between mb-3">
            <span className="px-2 py-0.5 rounded-full text-[10px] font-mono uppercase bg-[#DFE9E1] text-[#477C78]">
              {selectedNode.type}
            </span>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-[#738087] hover:text-[#202C32] p-1 rounded-lg hover:bg-black/5"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <h4 className="font-semibold text-sm text-[#202C32] mb-1 font-mono break-all">
            {selectedNode.name}
          </h4>

          <div className="space-y-2 mt-3 text-xs text-[#738087]">
            {selectedNode.severity && (
              <div className="flex justify-between">
                <span>Severity:</span>
                <span className="font-semibold uppercase text-[#202C32]">{selectedNode.severity}</span>
              </div>
            )}
            {selectedNode.review_state && (
              <div className="flex justify-between">
                <span>Review Status:</span>
                <span className="font-mono text-[#202C32]">{selectedNode.review_state}</span>
              </div>
            )}
            {selectedNode.confidence !== undefined && (
              <div className="flex justify-between">
                <span>Confidence Index:</span>
                <span className="font-mono text-[#202C32]">{selectedNode.confidence}%</span>
              </div>
            )}
            {selectedNode.occurrence_count && (
              <div className="flex justify-between">
                <span>Recorded Incidents:</span>
                <span className="font-mono text-[#202C32]">{selectedNode.occurrence_count}</span>
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-[#DDDCD3] text-[10px] text-[#738087]">
            ℹ️ Sourced from local SQLite threat intelligence repository. Only human-reviewed indicators participate in candidate training gates.
          </div>
        </div>
      )}
    </div>
  );
};
