"""
Attack Path Graph - Dynamic attack path discovery and modeling

NodeZero-inspired attack path chaining with graph-based modeling
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any, Tuple
from enum import Enum
import networkx as nx
from datetime import datetime

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Types of nodes in the attack graph"""
    ASSET = "asset"  # Target host/service
    VULNERABILITY = "vulnerability"  # Exploitable weakness
    CREDENTIAL = "credential"  # Discovered credentials
    ACCESS = "access"  # Level of access gained
    DATA = "data"  # Sensitive data discovered


class AccessLevel(Enum):
    """Levels of access"""
    NONE = 0
    USER = 1
    ADMIN = 2
    SYSTEM = 3
    DOMAIN_ADMIN = 4


@dataclass
class GraphNode:
    """Node in the attack graph"""
    node_id: str
    node_type: NodeType
    name: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    # Discovery info
    discovered_at: datetime = field(default_factory=datetime.now)
    discovered_by: Optional[str] = None  # Tool/technique that found it

    # Status
    accessed: bool = False
    exploited: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.node_id,
            'type': self.node_type.value,
            'name': self.name,
            'metadata': self.metadata,
            'discovered_at': self.discovered_at.isoformat(),
            'accessed': self.accessed,
            'exploited': self.exploited,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'GraphNode':
        """Reconstruct GraphNode from dictionary"""
        return GraphNode(
            node_id=data['id'],
            node_type=NodeType(data['type']),
            name=data['name'],
            metadata=data.get('metadata', {}),
            discovered_at=datetime.fromisoformat(data['discovered_at']) if data.get('discovered_at') else datetime.now(),
            accessed=data.get('accessed', False),
            exploited=data.get('exploited', False),
        )


@dataclass
class GraphEdge:
    """Edge representing a possible attack step"""
    edge_id: str
    source_id: str
    target_id: str

    # Attack details
    technique: str  # MITRE ATT&CK technique
    tool: str  # Tool to use
    description: str

    # Risk assessment
    complexity: str = "medium"  # low, medium, high
    detection_likelihood: str = "medium"  # low, medium, high
    success_probability: float = 0.5

    # Requirements
    requires_credentials: bool = False
    credential_id: Optional[str] = None
    prerequisites: List[str] = field(default_factory=list)

    # Execution
    attempted: bool = False
    successful: bool = False
    result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.edge_id,
            'source': self.source_id,
            'target': self.target_id,
            'technique': self.technique,
            'tool': self.tool,
            'description': self.description,
            'complexity': self.complexity,
            'detection_likelihood': self.detection_likelihood,
            'success_probability': self.success_probability,
            'attempted': self.attempted,
            'successful': self.successful,
            'executed': self.attempted,  # alias for compatibility
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'GraphEdge':
        """Reconstruct GraphEdge from dictionary"""
        return GraphEdge(
            edge_id=data['id'],
            source_id=data['source'],
            target_id=data['target'],
            technique=data['technique'],
            tool=data['tool'],
            description=data['description'],
            complexity=data.get('complexity', 'medium'),
            detection_likelihood=data.get('detection_likelihood', 'medium'),
            success_probability=data.get('success_probability', 0.5),
            requires_credentials=data.get('requires_credentials', False),
            attempted=data.get('attempted', False) or data.get('executed', False),
            successful=data.get('successful', False),
        )


class AttackPathGraph:
    """
    Graph-based attack path modeling

    Maintains a directed graph where:
    - Nodes = Assets, vulnerabilities, credentials, access levels
    - Edges = Attack steps (exploits, lateral movement, etc.)

    Supports:
    - Dynamic path discovery
    - Multi-hop lateral movement
    - Credential-based pivoting
    - Optimal path finding
    """

    def __init__(self, objective: str, initial_target: str):
        self.graph = nx.DiGraph()
        self.objective = objective
        self.initial_target = initial_target

        # Tracking
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: Dict[str, GraphEdge] = {}
        self.current_access_level = AccessLevel.NONE
        self.compromised_hosts: Set[str] = set()
        self.discovered_credentials: Set[str] = set()

        # Add initial target node
        self._add_initial_target()

    def _add_initial_target(self):
        """Add the initial target to the graph"""
        node = GraphNode(
            node_id="target_initial",
            node_type=NodeType.ASSET,
            name=self.initial_target,
            metadata={'asset_type': 'initial_target'},
        )
        self.add_node(node)

    def add_node(self, node: GraphNode):
        """Add a node to the graph"""
        self.nodes[node.node_id] = node
        self.graph.add_node(
            node.node_id,
            type=node.node_type.value,
            data=node.to_dict()
        )
        logger.debug(f"Added node: {node.node_id} ({node.node_type.value})")

    def add_edge(self, edge: GraphEdge):
        """Add an edge (attack step) to the graph"""
        self.edges[edge.edge_id] = edge
        self.graph.add_edge(
            edge.source_id,
            edge.target_id,
            edge_id=edge.edge_id,
            data=edge.to_dict()
        )
        logger.debug(f"Added edge: {edge.edge_id} ({edge.source_id} -> {edge.target_id})")

    def add_vulnerability(
        self,
        vuln_id: str,
        asset_id: str,
        name: str,
        exploit_info: Dict[str, Any]
    ):
        """Add a vulnerability and create exploitation edge"""
        # Add vulnerability node
        vuln_node = GraphNode(
            node_id=vuln_id,
            node_type=NodeType.VULNERABILITY,
            name=name,
            metadata=exploit_info,
        )
        self.add_node(vuln_node)

        # Create edge from asset to vulnerability
        edge = GraphEdge(
            edge_id=f"exploit_{vuln_id}",
            source_id=asset_id,
            target_id=vuln_id,
            technique=exploit_info.get('mitre_technique', 'T1190'),
            tool=exploit_info.get('tool', 'manual'),
            description=f"Exploit {name}",
            complexity=exploit_info.get('complexity', 'medium'),
            detection_likelihood=exploit_info.get('detection_risk', 'medium'),
            success_probability=exploit_info.get('success_rate', 0.7),
        )
        self.add_edge(edge)

    def add_credential(
        self,
        cred_id: str,
        source_asset: str,
        username: str,
        credential_type: str,
        metadata: Dict[str, Any]
    ):
        """Add discovered credentials"""
        cred_node = GraphNode(
            node_id=cred_id,
            node_type=NodeType.CREDENTIAL,
            name=f"{username} ({credential_type})",
            metadata={
                'username': username,
                'type': credential_type,
                'source_asset': source_asset,
                **metadata
            },
        )
        self.add_node(cred_node)
        self.discovered_credentials.add(cred_id)

        logger.info(f"🔑 Discovered credential: {username}")

    def add_lateral_movement_path(
        self,
        source_asset: str,
        target_asset: str,
        credential_id: Optional[str],
        technique: str,
        tool: str
    ):
        """Add a lateral movement path between assets"""
        edge = GraphEdge(
            edge_id=f"lateral_{source_asset}_to_{target_asset}",
            source_id=source_asset,
            target_id=target_asset,
            technique=technique,
            tool=tool,
            description=f"Lateral movement via {technique}",
            requires_credentials=(credential_id is not None),
            credential_id=credential_id,
            complexity="medium",
            detection_likelihood="high",
        )
        self.add_edge(edge)

    def find_paths_to_objective(
        self,
        start_node: str = "target_initial",
        max_hops: int = 5
    ) -> List[List[str]]:
        """
        Find all paths from current position to objective

        Returns:
            List of paths (each path is a list of node IDs)
        """
        # Find nodes matching the objective
        objective_nodes = self._find_objective_nodes()

        if not objective_nodes:
            logger.warning(f"No nodes found matching objective: {self.objective}")
            return []

        all_paths = []
        for target_node in objective_nodes:
            try:
                # Find all simple paths (no cycles)
                paths = nx.all_simple_paths(
                    self.graph,
                    source=start_node,
                    target=target_node,
                    cutoff=max_hops
                )
                all_paths.extend(list(paths))
            except nx.NetworkXNoPath:
                continue

        return all_paths

    def _find_objective_nodes(self) -> List[str]:
        """Find nodes that match the objective"""
        matching_nodes = []

        # Parse objective (e.g., "reach database server", "obtain domain admin")
        objective_lower = self.objective.lower()

        for node_id, node in self.nodes.items():
            # Check if node matches objective
            if 'database' in objective_lower and 'database' in node.name.lower():
                matching_nodes.append(node_id)
            elif 'domain admin' in objective_lower and node.node_type == NodeType.ACCESS:
                if node.metadata.get('access_level') == AccessLevel.DOMAIN_ADMIN.value:
                    matching_nodes.append(node_id)
            elif 'admin' in objective_lower and node.node_type == NodeType.ACCESS:
                if node.metadata.get('access_level') in [AccessLevel.ADMIN.value, AccessLevel.SYSTEM.value]:
                    matching_nodes.append(node_id)

        return matching_nodes

    def get_next_steps(
        self,
        from_node: str = "target_initial",
        filter_attempted: bool = True
    ) -> List[GraphEdge]:
        """
        Get possible next steps from current position

        Args:
            from_node: Starting node ID
            filter_attempted: Whether to filter out already attempted edges

        Returns:
            List of possible attack edges
        """
        possible_edges = []

        # Get all outgoing edges from current node
        if from_node in self.graph:
            for _, target, edge_data in self.graph.out_edges(from_node, data=True):
                edge_id = edge_data['edge_id']
                edge = self.edges.get(edge_id)

                if not edge:
                    continue

                # Filter attempted if requested
                if filter_attempted and edge.attempted:
                    continue

                # Check prerequisites
                if edge.prerequisites:
                    all_met = all(
                        self.edges.get(prereq_id, GraphEdge("", "", "", "", "", "")).successful
                        for prereq_id in edge.prerequisites
                    )
                    if not all_met:
                        continue

                # Check credential requirements
                if edge.requires_credentials and not edge.credential_id:
                    continue

                possible_edges.append(edge)

        # Sort by success probability (highest first)
        possible_edges.sort(key=lambda e: e.success_probability, reverse=True)

        return possible_edges

    def mark_edge_attempted(self, edge_id: str, success: bool, result: Dict[str, Any]):
        """Mark an edge as attempted with result"""
        edge = self.edges.get(edge_id)
        if edge:
            edge.attempted = True
            edge.successful = success
            edge.result = result

            if success:
                # Mark target node as accessed
                target_node = self.nodes.get(edge.target_id)
                if target_node:
                    target_node.accessed = True

                    if target_node.node_type == NodeType.ASSET:
                        self.compromised_hosts.add(target_node.node_id)

    def get_optimal_path_to_objective(self) -> Optional[List[GraphEdge]]:
        """
        Get the optimal (shortest, highest probability) path to objective

        Returns:
            List of edges representing the optimal attack path
        """
        paths = self.find_paths_to_objective()

        if not paths:
            return None

        # Score each path
        scored_paths = []
        for path_nodes in paths:
            edges_in_path = []
            total_score = 0.0

            for i in range(len(path_nodes) - 1):
                source = path_nodes[i]
                target = path_nodes[i + 1]

                # Find edge between these nodes
                edge_id = None
                for eid, edge in self.edges.items():
                    if edge.source_id == source and edge.target_id == target:
                        edge_id = eid
                        break

                if not edge_id:
                    total_score = 0  # Invalid path
                    break

                edge = self.edges[edge_id]
                edges_in_path.append(edge)

                # Score based on success probability and complexity
                complexity_penalty = {
                    'low': 0.9,
                    'medium': 0.7,
                    'high': 0.5
                }
                detection_penalty = {
                    'low': 0.9,
                    'medium': 0.8,
                    'high': 0.6
                }

                step_score = (
                    edge.success_probability *
                    complexity_penalty.get(edge.complexity, 0.7) *
                    detection_penalty.get(edge.detection_likelihood, 0.8)
                )
                total_score += step_score

            if total_score > 0:
                scored_paths.append((total_score / len(edges_in_path), edges_in_path))

        if not scored_paths:
            return None

        # Return path with highest score
        scored_paths.sort(key=lambda x: x[0], reverse=True)
        return scored_paths[0][1]

    def visualize_graph(self) -> str:
        """Generate ASCII visualization of the attack graph"""
        lines = []
        lines.append(f"\n{'='*60}")
        lines.append(f"Attack Path Graph: {self.objective}")
        lines.append(f"{'='*60}\n")

        lines.append(f"Nodes: {len(self.nodes)}")
        lines.append(f"  - Assets: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.ASSET)}")
        lines.append(f"  - Vulnerabilities: {sum(1 for n in self.nodes.values() if n.node_type == NodeType.VULNERABILITY)}")
        lines.append(f"  - Credentials: {len(self.discovered_credentials)}")
        lines.append(f"  - Compromised: {len(self.compromised_hosts)}\n")

        lines.append(f"Attack Paths: {len(self.edges)}")
        lines.append(f"  - Attempted: {sum(1 for e in self.edges.values() if e.attempted)}")
        lines.append(f"  - Successful: {sum(1 for e in self.edges.values() if e.successful)}\n")

        # Show optimal path if exists
        optimal = self.get_optimal_path_to_objective()
        if optimal:
            lines.append("Optimal Path to Objective:")
            for i, edge in enumerate(optimal, 1):
                lines.append(f"  {i}. {edge.description} (via {edge.tool})")
                lines.append(f"     Success: {edge.success_probability:.0%} | "
                           f"Complexity: {edge.complexity} | "
                           f"Detection: {edge.detection_likelihood}")
        else:
            lines.append("No path to objective found yet.")

        lines.append(f"\n{'='*60}\n")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Export graph to dictionary"""
        return {
            'objective': self.objective,
            'initial_target': self.initial_target,
            'nodes': [node.to_dict() for node in self.nodes.values()],
            'edges': [edge.to_dict() for edge in self.edges.values()],
            'compromised_hosts': list(self.compromised_hosts),
            'discovered_credentials': list(self.discovered_credentials),
            'current_access_level': self.current_access_level.value,
            'statistics': {
                'total_nodes': len(self.nodes),
                'total_edges': len(self.edges),
                'compromised_hosts': len(self.compromised_hosts),
                'discovered_credentials': len(self.discovered_credentials),
                'attempted_attacks': sum(1 for e in self.edges.values() if e.attempted),
                'successful_attacks': sum(1 for e in self.edges.values() if e.successful),
            }
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AttackPathGraph':
        """Reconstruct AttackPathGraph from saved dictionary"""
        # Create graph with objective and target
        graph = cls(
            objective=data['objective'],
            initial_target=data['initial_target']
        )

        # Clear the auto-created initial node (we'll restore from data)
        graph.nodes.clear()
        graph.edges.clear()
        graph.graph.clear()

        # Restore nodes
        for node_data in data.get('nodes', []):
            try:
                node = GraphNode.from_dict(node_data)
                graph.nodes[node.node_id] = node
                graph.graph.add_node(
                    node.node_id,
                    type=node.node_type.value,
                    data=node.to_dict()
                )
            except Exception as e:
                logger.warning(f"Failed to restore node: {e}")

        # Restore edges
        for edge_data in data.get('edges', []):
            try:
                edge = GraphEdge.from_dict(edge_data)
                graph.edges[edge.edge_id] = edge
                graph.graph.add_edge(
                    edge.source_id,
                    edge.target_id,
                    edge_id=edge.edge_id,
                    data=edge.to_dict()
                )
            except Exception as e:
                logger.warning(f"Failed to restore edge: {e}")

        # Restore tracking data
        graph.compromised_hosts = set(data.get('compromised_hosts', []))
        graph.discovered_credentials = set(data.get('discovered_credentials', []))

        # Restore access level
        access_level_str = data.get('current_access_level', 'none')
        try:
            graph.current_access_level = AccessLevel(access_level_str)
        except ValueError:
            graph.current_access_level = AccessLevel.NONE

        logger.info(f"📊 Restored attack graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
        return graph
