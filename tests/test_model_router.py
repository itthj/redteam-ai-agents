"""Tests for the cost-aware model router (5A)."""

import pytest

from config.settings import settings
from core.model_router import ModelRouter, router


def test_planning_routes_to_opus_xhigh():
    model, effort = router.pick("planning")
    assert model == settings.claude_model
    assert effort == "xhigh"


def test_exploit_decision_routes_to_opus_high():
    model, effort = router.pick("exploit_decision")
    assert model == settings.claude_model
    assert effort == "high"


@pytest.mark.parametrize("task_class", ["parse", "summarize", "classify"])
def test_mechanical_tasks_route_to_fast_model(task_class):
    model, effort = router.pick(task_class)
    assert model == settings.claude_fast_model
    assert effort == "low"


def test_unknown_task_falls_back_to_default():
    model, effort = router.pick("something_unrecognised")
    assert model == settings.claude_model
    assert effort == settings.agent_effort


def test_router_singleton_is_a_router():
    assert isinstance(router, ModelRouter)
