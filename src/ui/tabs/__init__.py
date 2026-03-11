"""UI Tabs Package"""
from .charts_tab import render_charts_tab
from .heatmaps_tab import render_heatmaps_tab
from .types_tab import render_types_ranking_tab
from .clusters_tab import render_clusters_tab
from .anomalies_tab import render_anomalies_tab
from .sequences_tab import render_sequences_tab

__all__ = [
    "render_charts_tab",
    "render_heatmaps_tab",
    "render_types_ranking_tab",
    "render_clusters_tab",
    "render_anomalies_tab",
    "render_sequences_tab",
]
