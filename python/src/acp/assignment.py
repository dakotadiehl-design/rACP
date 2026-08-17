"""Lyric assignment resolution — Conductor-owned, never inferred from song_id."""

from __future__ import annotations

from dataclasses import dataclass, field

REASONS = ("explicit_assignment", "performer_preference", "show_default", "fallback")


@dataclass
class Chart:
    asset_id: str
    song_id: str
    revision: int
    sha256: str
    chart_type: str


@dataclass
class AssignmentResolver:
    explicit: dict[tuple[str, str], Chart] = field(default_factory=dict)  # (song, participant)
    preferences: dict[str, str] = field(default_factory=dict)  # participant -> chart_type
    show_default_type: str = "chord_lyrics"
    catalog: list[Chart] = field(default_factory=list)
    bindings: dict[str, str] = field(default_factory=dict)  # device -> participant

    def bind(self, device_id: str, participant_id: str) -> None:
        self.bindings[device_id] = participant_id

    def resolve(self, song_id: str, participant_id: str) -> tuple[Chart | None, str | None]:
        key = (song_id, participant_id)
        if key in self.explicit:
            return self.explicit[key], "explicit_assignment"
        pref = self.preferences.get(participant_id)
        if pref:
            hit = self._find(song_id, pref)
            if hit:
                return hit, "performer_preference"
        hit = self._find(song_id, self.show_default_type)
        if hit:
            return hit, "show_default"
        for chart in self.catalog:
            if chart.song_id == song_id:
                return chart, "fallback"
        return None, None

    def _find(self, song_id: str, chart_type: str) -> Chart | None:
        for chart in self.catalog:
            if chart.song_id == song_id and chart.chart_type == chart_type:
                return chart
        return None


