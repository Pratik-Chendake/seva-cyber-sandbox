import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { WebGLFallback } from '../common/WebGLFallback';

interface NeuralLattice3DProps {
  operatingMode?: string;
}

export const NeuralLattice3D: React.FC<NeuralLattice3DProps> = ({ operatingMode = 'shadow' }) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [hasWebGL, setHasWebGL] = useState(true);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) {
        setHasWebGL(false);
        return;
      }
    } catch {
      setHasWebGL(false);
      return;
    }

    const width = container.clientWidth || 600;
    const height = container.clientHeight || 450;

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 11);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    container.appendChild(renderer.domElement);

    const group = new THREE.Group();
    scene.add(group);

    // Layer definitions (Representing custom MLP architecture: 64 -> 128 -> 64 -> 3)
    const layers = [
      { name: 'Input Features (64)', count: 8, x: -4.5, color: 0x738087 },
      { name: 'Hidden Layer 1 (128)', count: 12, x: -1.5, color: 0x477c78 },
      { name: 'Hidden Layer 2 (64)', count: 10, x: 1.5, color: 0x477c78 },
      { name: 'Output Decision (3)', count: 3, x: 4.5, color: 0xb8794b },
    ];

    const nodePositions: THREE.Vector3[][] = [];

    // Create neuron nodes
    layers.forEach((layer) => {
      const positions: THREE.Vector3[] = [];
      const ySpacing = 3.6 / (layer.count - 1 || 1);

      for (let i = 0; i < layer.count; i++) {
        const y = (i - (layer.count - 1) / 2) * ySpacing;
        const z = (Math.random() - 0.5) * 0.8;
        const pos = new THREE.Vector3(layer.x, y, z);
        positions.push(pos);

        const nodeGeo = new THREE.SphereGeometry(0.12, 16, 16);
        const nodeMat = new THREE.MeshStandardMaterial({
          color: layer.color,
          emissive: layer.color,
          emissiveIntensity: 0.35,
          roughness: 0.3,
          metalness: 0.2,
        });
        const mesh = new THREE.Mesh(nodeGeo, nodeMat);
        mesh.position.copy(pos);
        group.add(mesh);
      }
      nodePositions.push(positions);
    });

    // Create synaptic connection lines
    const lineMat = new THREE.LineBasicMaterial({
      color: 0xdddcd3,
      transparent: true,
      opacity: 0.25,
    });

    for (let l = 0; l < nodePositions.length - 1; l++) {
      const currentLayer = nodePositions[l];
      const nextLayer = nodePositions[l + 1];

      for (let i = 0; i < currentLayer.length; i++) {
        for (let j = 0; j < nextLayer.length; j++) {
          if (Math.random() > 0.45) {
            const points = [currentLayer[i], nextLayer[j]];
            const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
            const line = new THREE.Line(lineGeo, lineMat);
            group.add(line);
          }
        }
      }
    }

    // Interactive mouse rotation
    let mouseX = 0;
    let mouseY = 0;
    const onMouseMove = (e: MouseEvent) => {
      const rect = container.getBoundingClientRect();
      mouseX = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      mouseY = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
    };
    container.addEventListener('mousemove', onMouseMove);

    // Animation Loop
    let animId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animId = requestAnimationFrame(animate);
      const t = clock.getElapsedTime();

      group.rotation.y = Math.sin(t * 0.4) * 0.15 + mouseX * 0.25;
      group.rotation.x = -mouseY * 0.2;

      renderer.render(scene, camera);
    };
    animate();

    const onResize = () => {
      if (!container) return;
      const w = container.clientWidth;
      const h = container.clientHeight;
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      renderer.setSize(w, h);
    };
    window.addEventListener('resize', onResize);

    return () => {
      cancelAnimationFrame(animId);
      container.removeEventListener('mousemove', onMouseMove);
      window.removeEventListener('resize', onResize);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
    };
  }, []);

  if (!hasWebGL) {
    return <WebGLFallback title="Neural Architecture Lattice (2D Standby)" />;
  }

  return (
    <div className="relative w-full h-[400px] rounded-2xl overflow-hidden liquid-glass">
      <div ref={mountRef} className="w-full h-full cursor-grab" />
      <div className="absolute top-3 left-4 z-10">
        <span className="glass-pill px-3 py-1 text-[10px] font-mono tracking-wider uppercase text-[#738087] flex items-center gap-1.5 shadow-sm">
          <span className="w-1.5 h-1.5 rounded-full bg-[#477C78] animate-pulse" />
          <span>Architecture: Scratch 3-Layer MLP // Operating: {operatingMode.toUpperCase()} MODE</span>
        </span>
      </div>
    </div>
  );
};
