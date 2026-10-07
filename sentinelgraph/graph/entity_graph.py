"""Temporal attack graph engine using NetworkX and JSON serialization."""
from typing import Dict, List, Optional
import networkx as nx
from sentinelgraph.models import Incident, GraphNode, GraphEdge, TemporalGraphData, NormalizedEvent


class GraphEngine:
    """Builds multi-entity temporal attack graphs from incidents and events."""

    @classmethod
    def build_incident_graph(
        cls,
        incident: Incident,
        events: Optional[List[NormalizedEvent]] = None
    ) -> TemporalGraphData:
        """Construct a temporal entity graph for a specific incident."""
        G = nx.DiGraph()
        nodes_dict: Dict[str, GraphNode] = {}
        edges_list: List[GraphEdge] = []

        # Add Incident root node
        inc_node = GraphNode(
            id=incident.incident_id,
            label=f"{incident.incident_id}: {incident.severity}",
            node_type="Incident",
            status="confirmed" if incident.severity in ("HIGH", "CRITICAL") else "suspicious",
            color="#EF4444" if incident.severity in ("HIGH", "CRITICAL") else "#F59E0B",
            metadata={"risk": incident.risk_score, "confidence": incident.confidence}
        )
        nodes_dict[inc_node.id] = inc_node

        # Add Users
        for u in incident.affected_users:
            nid = f"USER-{u}"
            if nid not in nodes_dict:
                nodes_dict[nid] = GraphNode(
                    id=nid,
                    label=f"User: {u}",
                    node_type="User",
                    status="suspicious",
                    color="#F59E0B"
                )
            edges_list.append(
                GraphEdge(source=incident.incident_id, target=nid, relationship="involved_user", color="#EF4444")
            )

        # Add Devices
        for d in incident.affected_devices:
            nid = f"DEV-{d}"
            if nid not in nodes_dict:
                nodes_dict[nid] = GraphNode(
                    id=nid,
                    label=f"Endpoint: {d}",
                    node_type="Device",
                    status="suspicious",
                    color="#F59E0B"
                )
            # Connect User to Device
            for u in incident.affected_users:
                edges_list.append(
                    GraphEdge(source=f"USER-{u}", target=nid, relationship="logged_into", color="#EF4444")
                )

        # Add IPs and Countries
        for ip in incident.affected_ips:
            nid = f"IP-{ip}"
            if nid not in nodes_dict:
                nodes_dict[nid] = GraphNode(
                    id=nid,
                    label=f"IP: {ip}",
                    node_type="IP",
                    status="suspicious",
                    color="#F59E0B"
                )
            for u in incident.affected_users:
                edges_list.append(
                    GraphEdge(source=nid, target=f"USER-{u}", relationship="authenticated_from", color="#F59E0B")
                )

        for c in incident.affected_countries:
            nid = f"GEO-{c}"
            if nid not in nodes_dict:
                nodes_dict[nid] = GraphNode(
                    id=nid,
                    label=f"Country: {c}",
                    node_type="Country",
                    status="suspicious",
                    color="#F59E0B"
                )
            for ip in incident.affected_ips:
                edges_list.append(
                    GraphEdge(source=nid, target=f"IP-{ip}", relationship="originates_from", color="#38BDF8")
                )

        # Add Sensitive Files
        for f in incident.affected_files:
            nid = f"FILE-{f}"
            if nid not in nodes_dict:
                nodes_dict[nid] = GraphNode(
                    id=nid,
                    label=f"File: {f}",
                    node_type="File",
                    status="confirmed",
                    color="#EF4444"
                )
            for d in incident.affected_devices:
                edges_list.append(
                    GraphEdge(source=f"DEV-{d}", target=nid, relationship="accessed", color="#EF4444")
                )

        # Add USB Removable Media
        for usb in incident.affected_usb_devices:
            nid = f"USB-{usb}"
            if nid not in nodes_dict:
                nodes_dict[nid] = GraphNode(
                    id=nid,
                    label=f"USB: {usb}",
                    node_type="USB",
                    status="confirmed",
                    color="#EF4444"
                )
            for d in incident.affected_devices:
                edges_list.append(
                    GraphEdge(source=f"DEV-{d}", target=nid, relationship="connected", color="#EF4444")
                )
            for f in incident.affected_files:
                edges_list.append(
                    GraphEdge(source=f"FILE-{f}", target=nid, relationship="copied_to", color="#EF4444")
                )

        # Add Destinations
        for dst in incident.affected_destinations:
            nid = f"DST-{dst}"
            if nid not in nodes_dict:
                nodes_dict[nid] = GraphNode(
                    id=nid,
                    label=f"Dest: {dst}",
                    node_type="Destination",
                    status="confirmed",
                    color="#EF4444"
                )
            for d in incident.affected_devices:
                edges_list.append(
                    GraphEdge(source=f"DEV-{d}", target=nid, relationship="transferred_to", color="#EF4444")
                )

        # Add Temporal Sequence between Evidence Events
        if events:
            sorted_e = sorted(events, key=lambda e: (e.timestamp, e.event_id))
            for i in range(len(sorted_e) - 1):
                e_curr = sorted_e[i]
                e_next = sorted_e[i + 1]
                edges_list.append(
                    GraphEdge(
                        source=f"DEV-{e_curr.device_id}" if e_curr.device_id else incident.incident_id,
                        target=f"DEV-{e_next.device_id}" if e_next.device_id else incident.incident_id,
                        relationship="occurred_before",
                        color="#64748B",
                        timestamp=e_curr.timestamp
                    )
                )

        return TemporalGraphData(
            nodes=list(nodes_dict.values()),
            edges=edges_list
        )
