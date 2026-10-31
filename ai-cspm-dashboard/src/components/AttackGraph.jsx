import React, { useState } from 'react';
import { Server, Shield, Key, Database, FileCode, AlertTriangle, CheckCircle2 } from './Icons';

export default function AttackGraph({ nodes, edges, attackPaths }) {
  const [selectedNode, setSelectedNode] = useState(null);

  // Position nodes strategically across 4 architectural tiers
  const layoutPositions = {
    'k8s:workload:production:payment-processor-deployment': { x: 120, y: 160, layer: 'Kubernetes', color: '#c084fc' },
    'k8s:sa:production:payment-service-sa': { x: 380, y: 160, layer: 'Kubernetes', color: '#c084fc' },
    'iam:role:eks-payment-kms-role': { x: 640, y: 160, layer: 'AWS IAM', color: '#38bdf8' },
    'iam:policy:OverprivilegedPaymentKmsPolicy': { x: 640, y: 340, layer: 'AWS IAM', color: '#f43f5e', isVulnerable: true },
    'kms:key:payment_key': { x: 920, y: 250, layer: 'Cryptography', color: '#fbbf24' },
    's3:bucket:payment_vault': { x: 1180, y: 250, layer: 'Cloud Storage', color: '#10b981' }
  };

  const getNodeIcon = (type) => {
    switch (type) {
      case 'WORKLOAD': return <Server size={20} color="#c084fc" />;
      case 'SERVICE_ACCOUNT': return <Shield size={20} color="#c084fc" />;
      case 'IAM_ROLE': return <Shield size={20} color="#38bdf8" />;
      case 'IAM_POLICY': return <FileCode size={20} color="#f43f5e" />;
      case 'KMS_KEY': return <Key size={20} color="#fbbf24" />;
      case 'S3_BUCKET': return <Database size={20} color="#10b981" />;
      default: return <Server size={20} />;
    }
  };

  return (
    <div style={{ position: 'relative', width: '100%', overflowX: 'auto' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h3 style={{ fontSize: 18, fontWeight: 700, color: '#f8fafc' }}>
            🕸️ Contextual Multi-Tier Directed Acyclic Graph (DAG)
          </h3>
          <p style={{ fontSize: 13, color: '#94a3b8' }}>
            Click on any node to inspect extracted properties across container, identity, and cryptographic tiers.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 16, fontSize: 12 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#c084fc' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#c084fc' }}></span> Kubernetes Tier
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#38bdf8' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#38bdf8' }}></span> Cloud IAM Tier
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#fbbf24' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#fbbf24' }}></span> KMS Cryptography
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#10b981' }}>
            <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#10b981' }}></span> Target S3 Vault
          </span>
        </div>
      </div>

      <div style={{
        background: '#070a12',
        border: '1px solid #1e293b',
        borderRadius: 14,
        padding: 24,
        position: 'relative',
        minWidth: 1300,
        height: 520
      }}>
        <svg style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}>
          <defs>
            <linearGradient id="edgeGradVulnerable" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f43f5e" />
              <stop offset="100%" stopColor="#fbbf24" />
            </linearGradient>
            <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#475569" />
            </marker>
            <marker id="arrowDanger" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#f43f5e" />
            </marker>
          </defs>

          {/* Render Graph Edges */}
          {edges.map((e, idx) => {
            const src = layoutPositions[e.source] || { x: 100, y: 100 };
            const tgt = layoutPositions[e.target] || { x: 300, y: 300 };
            const isFlaw = e.is_wildcard || e.type === 'ALLOWS_DECRYPT' || e.type === 'IRSA_ASSUMES';

            return (
              <g key={idx}>
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke={isFlaw ? '#f43f5e' : '#334155'}
                  strokeWidth={isFlaw ? 2.5 : 1.5}
                  strokeDasharray={isFlaw ? '6,4' : 'none'}
                  markerEnd={isFlaw ? 'url(#arrowDanger)' : 'url(#arrow)'}
                />
                <text
                  x={(src.x + tgt.x) / 2}
                  y={(src.y + tgt.y) / 2 - 8}
                  fill={isFlaw ? '#fda4af' : '#64748b'}
                  fontSize={10}
                  fontWeight={600}
                  textAnchor="middle"
                  fontFamily="JetBrains Mono"
                >
                  {e.type}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Render Graph Nodes */}
        {nodes.map((node) => {
          const pos = layoutPositions[node.id] || { x: 200, y: 200, layer: 'Unknown', color: '#94a3b8' };
          const isSelected = selectedNode?.id === node.id;
          const isVulnerable = pos.isVulnerable;

          return (
            <div
              key={node.id}
              onClick={() => setSelectedNode(node)}
              style={{
                position: 'absolute',
                left: pos.x - 100,
                top: pos.y - 45,
                width: 200,
                background: isSelected ? '#1e293b' : '#0f172a',
                border: `2px solid ${isVulnerable ? '#f43f5e' : isSelected ? '#38bdf8' : pos.color}`,
                boxShadow: isVulnerable
                  ? '0 0 20px rgba(244, 63, 94, 0.35)'
                  : isSelected
                  ? '0 0 16px rgba(56, 189, 248, 0.3)'
                  : '0 4px 12px rgba(0,0,0,0.5)',
                borderRadius: 12,
                padding: '12px 14px',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                zIndex: 10
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{
                  fontSize: 10,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  color: pos.color,
                  letterSpacing: 0.5
                }}>
                  {pos.layer}
                </span>
                {getNodeIcon(node.type)}
              </div>
              <div style={{
                fontSize: 12,
                fontWeight: 700,
                color: '#f8fafc',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis'
              }}>
                {node.label}
              </div>
              <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                {node.type}
              </div>
            </div>
          );
        })}
      </div>

      {/* Node Inspector Modal / Drawer */}
      {selectedNode && (
        <div style={{
          marginTop: 16,
          background: '#0f172a',
          border: '1px solid #334155',
          borderRadius: 12,
          padding: 16,
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <span style={{ fontSize: 11, color: '#38bdf8', fontWeight: 700, textTransform: 'uppercase' }}>
              Selected Asset Inspector
            </span>
            <h4 style={{ fontSize: 15, fontWeight: 700, color: '#f8fafc', marginTop: 2 }}>
              {selectedNode.label} ({selectedNode.type})
            </h4>
            <p style={{ fontSize: 12, color: '#94a3b8' }}>
              ID: <code style={{ color: '#c084fc' }}>{selectedNode.id}</code> | Source: {selectedNode.source_file}
            </p>
          </div>
          <button
            onClick={() => setSelectedNode(null)}
            style={{
              background: '#1e293b',
              border: 'none',
              color: '#94a3b8',
              padding: '6px 14px',
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 12
            }}
          >
            Close
          </button>
        </div>
      )}
    </div>
  );
}
