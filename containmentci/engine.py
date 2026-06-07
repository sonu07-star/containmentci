from __future__ import annotations

import asyncio
import time

from containmentci.evidence import append_event, sign_run
from containmentci.models import (
    CheckResult,
    CheckStatus,
    RunResult,
    RunStatus,
    ScenarioConfig,
    TargetConfig,
    utc_now,
)
from containmentci.providers import (
    GitHubRepositoryAccessProvider,
    HttpProvider,
    ProviderRegistry,
    SimulationProvider,
)


def default_registry() -> ProviderRegistry:
    registry = ProviderRegistry()
    registry.register("simulation", SimulationProvider)
    registry.register("http", HttpProvider)
    registry.register("github-repository-access", GitHubRepositoryAccessProvider)
    return registry


class ExecutionEngine:
    def __init__(self, registry: ProviderRegistry | None = None, allow_live: bool = False) -> None:
        self.registry = registry or default_registry()
        self.allow_live = allow_live

    def preflight(self, scenario: ScenarioConfig) -> list[str]:
        problems: list[str] = []
        for target in scenario.targets:
            try:
                provider = self.registry.create(target.provider)
            except ValueError as exc:
                problems.append(f"{target.name}: {exc}")
                continue
            problems.extend(provider.validate(scenario.identity, target))
        return problems

    async def run(self, scenario: ScenarioConfig) -> RunResult:
        run = RunResult(scenario=scenario.name, identity=scenario.identity)
        append_event(run.events, "run.started", data={"scenario": scenario.name})

        tasks = [self._execute_target(run, scenario, target) for target in scenario.targets]
        run.checks = list(await asyncio.gather(*tasks))
        run.status = (
            RunStatus.PASS
            if run.checks and all(check.status == CheckStatus.PASS for check in run.checks)
            else RunStatus.FAIL
        )
        run.finished_at = utc_now()
        append_event(
            run.events,
            "run.finished",
            data={"status": run.status, "coverage_percent": run.coverage_percent},
        )
        run.signature = sign_run(run)
        return run

    async def _execute_target(
        self, run: RunResult, scenario: ScenarioConfig, target: TargetConfig
    ) -> CheckResult:
        check = CheckResult(
            target=target.name,
            provider=target.provider,
            resource=target.resource,
        )
        started = time.monotonic()
        provider = self.registry.create(target.provider)

        try:
            if target.provider != "simulation" and not self.allow_live:
                raise PermissionError(
                    "Live provider execution requires explicit approval with --approve-live"
                )
            baseline = await provider.verify_access(scenario.identity, target)
            check.baseline_access = baseline.success
            append_event(
                run.events,
                "access.baseline",
                target.name,
                {"accessible": baseline.success, **baseline.evidence},
            )
            if not baseline.success:
                check.status = CheckStatus.ERROR
                check.message = "Baseline access failed; containment cannot be proven"
                return check

            containment = await provider.contain(scenario.identity, target)
            check.containment_requested = containment.success
            append_event(
                run.events,
                "containment.requested",
                target.name,
                {"accepted": containment.success, **containment.evidence},
            )
            if not containment.success:
                check.status = CheckStatus.ERROR
                check.message = containment.message
                return check

            deadline = time.monotonic() + scenario.timeout_seconds
            while time.monotonic() < deadline:
                check.attempts += 1
                probe = await provider.verify_access(scenario.identity, target)
                append_event(
                    run.events,
                    "access.probe",
                    target.name,
                    {"attempt": check.attempts, "accessible": probe.success, **probe.evidence},
                )
                if not probe.success:
                    check.status = CheckStatus.PASS
                    check.access_revoked = True
                    check.message = probe.message
                    check.evidence = probe.evidence
                    break
                await asyncio.sleep(scenario.poll_interval_seconds)
            else:
                check.status = CheckStatus.FAIL
                check.message = "Access remained active after the containment deadline"
                check.evidence = {"deadline_seconds": scenario.timeout_seconds}
        except Exception as exc:  # Providers are external boundaries.
            check.status = CheckStatus.ERROR
            check.message = f"{type(exc).__name__}: {exc}"
            append_event(run.events, "target.error", target.name, {"error": check.message})
        finally:
            check.elapsed_seconds = round(time.monotonic() - started, 3)
        return check
