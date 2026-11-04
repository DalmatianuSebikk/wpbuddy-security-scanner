"""Shared scan engine: the single orchestration path behind CLI and TUI.

`phases` is the declarative graph (order, preconditions, docs, effects),
`events` is the typed event bus, `run` executes the graph and `reporting`
holds the finalization writers. Nothing here imports Rich or Textual, so the
plain CLI and a future TUI observe exactly the same run.
"""
