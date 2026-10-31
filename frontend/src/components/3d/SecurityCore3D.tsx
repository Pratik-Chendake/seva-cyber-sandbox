import React, { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { WebGLFallback } from '../common/WebGLFallback';

interface SecurityCore3DProps {
  onSelectCore?: () => void;
}

export const SecurityCore3D: React.FC<SecurityCore3DProps> = ({ onSelectCore }) => {
  const mountRef = useRef<HTMLDivElement>(null);
  const [hasWebGL, setHasWebGL] = useState<boolean>(true);
  const [isHovered, setIsHovered] = useState<boolean>(false);
  const [rotationSpeed, setRotationSpeed] = useState<number>(0.006);

  useEffect(() => {
    const container = mountRef.current;
    if (!container) return;

    // 1. Check WebGL support
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

    const width = container.clientWidth || 500;
    const height = container.clientHeight || 500;

    // 2. Scene, Camera, Renderer
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 100);
    camera.position.set(0, 0, 7.5);

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.2;
    container.appendChild(renderer.domElement);

    // 3. Lighting (Soft Studio Lights for Liquid Glass Refraction)
    const ambientLight = new THREE.AmbientLight(0xf5f3ec, 1.8);
    scene.add(ambientLight);

    const keyLight = new THREE.DirectionalLight(0xffffff, 2.4);
    keyLight.position.set(5, 8, 6);
    scene.add(keyLight);

    const tealFillLight = new THREE.PointLight(0x477c78, 3.2, 15);
    tealFillLight.position.set(-5, -2, 4);
    scene.add(tealFillLight);

    const copperRimLight = new THREE.DirectionalLight(0xb8794b, 1.6);
    copperRimLight.position.set(3, -4, -3);
    scene.add(copperRimLight);

    // 4. Construct 3D Security Shield Geometry
    // Using a multifaceted extruded custom shield shape
    const shieldShape = new THREE.Shape();
    shieldShape.moveTo(0, 1.8);
    shieldShape.bezierCurveTo(1.4, 1.8, 1.8, 1.4, 1.8, 0.6);
    shieldShape.bezierCurveTo(1.8, -0.6, 1.0, -1.6, 0, -2.2);
    shieldShape.bezierCurveTo(-1.0, -1.6, -1.8, -0.6, -1.8, 0.6);
    shieldShape.bezierCurveTo(-1.8, 1.4, -1.4, 1.8, 0, 1.8);

    const extrudeSettings = {
      depth: 0.35,
      bevelEnabled: true,
      bevelSegments: 6,
      steps: 2,
      bevelSize: 0.12,
      bevelThickness: 0.15,
    };

    const shieldGeo = new THREE.ExtrudeGeometry(shieldShape, extrudeSettings);
    shieldGeo.center();

    // Liquid Glass Material (Translucent with Refraction & Mineral Highlights)
    const glassMaterial = new THREE.MeshPhysicalMaterial({
      color: 0xfaf8f2,
      metalness: 0.1,
      roughness: 0.12,
      transmission: 0.88,
      thickness: 1.2,
      ior: 1.52,
      reflectivity: 0.7,
      clearcoat: 1.0,
      clearcoatRoughness: 0.1,
      transparent: true,
      opacity: 0.92,
    });

    const shieldMesh = new THREE.Mesh(shieldGeo, glassMaterial);
    scene.add(shieldMesh);

    // Inner Core Emblem (Solid Mineral Teal Geometric Prism)
    const coreGeo = new THREE.OctahedronGeometry(0.7, 0);
    const coreMat = new THREE.MeshStandardMaterial({
      color: 0x477c78,
      metalness: 0.4,
      roughness: 0.3,
      emissive: 0x477c78,
      emissiveIntensity: 0.35,
    });
    const coreMesh = new THREE.Mesh(coreGeo, coreMat);
    shieldMesh.add(coreMesh);

    // Outer Orbiting Security Rings (Soft Stone & Copper)
    const ringGeo = new THREE.TorusGeometry(2.3, 0.02, 16, 100);
    const ringMat = new THREE.MeshStandardMaterial({
      color: 0xb8794b,
      metalness: 0.5,
      roughness: 0.4,
    });
    const orbitRing = new THREE.Mesh(ringGeo, ringMat);
    orbitRing.rotation.x = Math.PI / 3;
    scene.add(orbitRing);

    const ringGeo2 = new THREE.TorusGeometry(2.6, 0.015, 16, 100);
    const ringMat2 = new THREE.MeshStandardMaterial({
      color: 0x477c78,
      metalness: 0.6,
      roughness: 0.3,
    });
    const orbitRing2 = new THREE.Mesh(ringGeo2, ringMat2);
    orbitRing2.rotation.x = -Math.PI / 4;
    orbitRing2.rotation.y = Math.PI / 6;
    scene.add(orbitRing2);

    // Floating Glass Platform Below
    const platformGeo = new THREE.CylinderGeometry(2.2, 2.4, 0.1, 48);
    const platformMat = new THREE.MeshPhysicalMaterial({
      color: 0xf5f3ec,
      transmission: 0.8,
      opacity: 0.75,
      roughness: 0.2,
      transparent: true,
    });
    const platform = new THREE.Mesh(platformGeo, platformMat);
    platform.position.y = -2.7;
    scene.add(platform);

    // 5. Mouse Interaction & Pointer Tracking
    let mouseX = 0;
    let mouseY = 0;
    let targetRotationX = 0;
    let targetRotationY = 0;
    let isDragging = false;
    let prevPointerX = 0;

    const handlePointerMove = (e: PointerEvent) => {
      const rect = container.getBoundingClientRect();
      const x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
      const y = -(((e.clientY - rect.top) / rect.height) * 2 - 1);
      mouseX = x;
      mouseY = y;

      if (isDragging) {
        const deltaX = e.clientX - prevPointerX;
        shieldMesh.rotation.y += deltaX * 0.01;
        prevPointerX = e.clientX;
      }
    };

    const handlePointerDown = (e: PointerEvent) => {
      isDragging = true;
      prevPointerX = e.clientX;
    };

    const handlePointerUp = () => {
      isDragging = false;
    };

    container.addEventListener('pointermove', handlePointerMove);
    container.addEventListener('pointerdown', handlePointerDown);
    window.addEventListener('pointerup', handlePointerUp);

    // 6. Animation Loop
    let animationId: number;
    let clock = new THREE.Clock();

    const animate = () => {
      animationId = requestAnimationFrame(animate);
      const elapsedTime = clock.getElapsedTime();

      // Gentle floating animation
      shieldMesh.position.y = Math.sin(elapsedTime * 1.5) * 0.12;
      coreMesh.rotation.y = elapsedTime * 0.8;
      coreMesh.rotation.x = elapsedTime * 0.5;

      // Orbit rings rotation
      orbitRing.rotation.z = elapsedTime * 0.2;
      orbitRing2.rotation.z = -elapsedTime * 0.15;

      // Mouse responsive tilt
      targetRotationY = mouseX * 0.5;
      targetRotationX = -mouseY * 0.4;

      if (!isDragging) {
        shieldMesh.rotation.y += (targetRotationY - shieldMesh.rotation.y) * 0.05 + rotationSpeed;
      }
      shieldMesh.rotation.x += (targetRotationX - shieldMesh.rotation.x) * 0.05;

      renderer.render(scene, camera);
    };

    animate();

    // 7. Responsive Resize Handler
    const handleResize = () => {
      if (!container) return;
      const newW = container.clientWidth;
      const newH = container.clientHeight;
      camera.aspect = newW / newH;
      camera.updateProjectionMatrix();
      renderer.setSize(newW, newH);
    };

    window.addEventListener('resize', handleResize);

    return () => {
      cancelAnimationFrame(animationId);
      container.removeEventListener('pointermove', handlePointerMove);
      container.removeEventListener('pointerdown', handlePointerDown);
      window.removeEventListener('pointerup', handlePointerUp);
      window.removeEventListener('resize', handleResize);
      if (renderer.domElement && container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement);
      }
      renderer.dispose();
      shieldGeo.dispose();
      coreGeo.dispose();
      ringGeo.dispose();
      ringGeo2.dispose();
      platformGeo.dispose();
      glassMaterial.dispose();
      coreMat.dispose();
      ringMat.dispose();
      ringMat2.dispose();
      platformMat.dispose();
    };
  }, [rotationSpeed]);

  if (!hasWebGL) {
    return <WebGLFallback title="3D Security Core (2D Standby)" onRetry={() => setHasWebGL(true)} />;
  }

  return (
    <div
      ref={mountRef}
      onClick={onSelectCore}
      onMouseEnter={() => {
        setIsHovered(true);
        setRotationSpeed(0.015);
      }}
      onMouseLeave={() => {
        setIsHovered(false);
        setRotationSpeed(0.006);
      }}
      className="w-full h-full min-h-[460px] relative cursor-grab active:cursor-grabbing select-none"
    >
      {/* Interactive Tooltip Pill */}
      <div className="absolute bottom-4 left-1/2 -translate-x-1/2 pointer-events-none">
        <span className="glass-pill px-3 py-1 text-[11px] text-[#738087] font-mono tracking-wider uppercase flex items-center gap-1.5 shadow-sm">
          <span className="w-1.5 h-1.5 rounded-full bg-[#477C78] animate-pulse" />
          <span>{isHovered ? 'Drag to rotate // Click to inspect core' : 'Interactive 3D Glass Shield'}</span>
        </span>
      </div>
    </div>
  );
};
