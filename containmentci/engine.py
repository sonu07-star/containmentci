from __future__ import annotations

import asyncio
import time

from containmentci.evidence import append_event, sign_run, signing_key_is_configured
from containmentci.lease import FixtureLease
from containmentci.models import (
    AccessState,
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
        live_target_names: list[str] = []
        for target in scenario.targets:
            try:
                provider = self.registry.create(target.provider)
            except ValueError as exc:
                problems.append(f"{target.name}: {exc}")
                continue
            if provider.requires_live_approval:
                live_target_names.append(target.name)
            try:
                problems.extend(provider.validate(scenario.identity, target))
                if target.control_required and not provider.has_control_probe(target):
                    problems.append(
                        f"{target.name}: control_required is true but no independent control "
                        "probe is configured"
                    )
            except Exception as exc:
                problems.append(
                    f"{target.name}: provider preflight raised {type(exc).__name__}: {exc}"
                )
        if len(live_target_names) > 1:
            problems.append(
                "Live scenarios support exactly one state-changing target so delayed effects "
                "cannot be credited to another control; split these targets into isolated "
                f"fixtures and scenarios: {', '.join(live_target_names)}"
            )
        return problems

    async def run(self, scenario: ScenarioConfig) -> RunResult:
        problems = self.preflight(scenario)
        if problems:
            raise ValueError("Scenario preflight failed: " + "; ".join(problems))
        live_targets = [
            target
            for target in scenario.targets
            if self.registry.create(target.provider).requires_live_approval
        ]
        if self.allow_live and live_targets and not signing_key_is_configured():
            raise PermissionError(
                "Live provider execution requires a signing key of at least 32 bytes"
            )
        if self.allow_live and live_targets:
            expected_runtime = sum(
                target.max_containment_seconds or scenario.timeout_seconds
                for target in scenario.targets
            ) + 2 * scenario.provider_timeout_seconds * len(scenario.targets)
            lease = FixtureLease(
                scenario.identity,
                {target.resource for target in live_targets},
                ttl_seconds=max(3600, expected_runtime * 2 + 60),
            )
            with lease.hold():
                return await self._run_scenario(scenario)
        return await self._run_scenario(scenario)

    async def _run_scenario(self, scenario: ScenarioConfig) -> RunResult:
        run = RunResult(scenario=scenario.name, identity=scenario.identity)
        append_event(run.events, "run.started", data={"scenario": scenario.name})

        # Simulation targets execute serially for deterministic transcripts. Preflight limits a
        # live scenario to one state-changing target so propagation cannot cross-credit targets.
        run.checks = []
        for target in scenario.targets:
            run.checks.append(await self._execute_target(run, scenario, target))
        if any(check.status == CheckStatus.ERROR for check in run.checks):
            run.status = RunStatus.ERROR
        elif run.checks and all(check.status == CheckStatus.PASS for check in run.checks):
            run.status = RunStatus.PASS
        else:
            run.status = RunStatus.FAIL
        run.finished_at = utc_now()
        append_event(
            run.events,
            "run.finished",
            data={"status": run.status, "coverage_percent": run.coverage_percent},
        )
        run.evidence_key_mode = (
            "configured-hmac" if signing_key_is_configured() else "development-hmac"
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
            containment_slo_seconds=target.max_containment_seconds or scenario.timeout_seconds,
        )
        started = time.monotonic()

        try:
            provider = self.registry.create(target.provider)
            if provider.requires_live_approval and not self.allow_live:
                raise PermissionError(
                    "Live provider execution requires explicit approval with --approve-live"
                )
            control_enabled = target.control_required or provider.has_control_probe(target)
            check.proof_mode = (
                provider.control_proof_mode(target) if control_enabled else "subject-only"
            )
            baseline = await asyncio.wait_for(
                provider.verify_access(scenario.identity, target),
                timeout=scenario.provider_timeout_seconds,
            )
            check.baseline_access = baseline.state == AccessState.ALLOWED
            append_event(
                run.events,
                "access.baseline",
                target.name,
                {**baseline.evidence, "state": baseline.state},
            )
            if baseline.state != AccessState.ALLOWED:
                check.status = CheckStatus.ERROR
                check.message = (
                    "Baseline access was not allowed; containment cannot be proven "
                    f"({baseline.state})"
                )
                return check

            control_baseline = None
            if control_enabled:
                control_baseline = await asyncio.wait_for(
                    provider.verify_control_access(scenario.identity, target),
                    timeout=scenario.provider_timeout_seconds,
                )
                control_state = (
                    control_baseline.state
                    if control_baseline is not None
                    else AccessState.INDETERMINATE
                )
                check.control_accessible = control_state == AccessState.ALLOWED
                append_event(
                    run.events,
                    "access.control_baseline",
                    target.name,
                    {
                        **(control_baseline.evidence if control_baseline else {}),
                        "state": control_state,
                    },
                )
                if control_state != AccessState.ALLOWED:
                    check.status = CheckStatus.ERROR
                    check.message = (
                        "Control access was not allowed at baseline; a healthy witness "
                        "cannot be established"
                    )
                    return check

            containment_started = time.monotonic()
            deadline = containment_started + check.containment_slo_seconds
            containment = await asyncio.wait_for(
                provider.contain(scenario.identity, target),
                timeout=min(
                    scenario.provider_timeout_seconds,
                    check.containment_slo_seconds,
                ),
            )
            check.containment_requested = containment.success
            append_event(
                run.events,
                "containment.requested",
                target.name,
                {**containment.evidence, "accepted": containment.success},
            )
            if not containment.success:
                check.status = CheckStatus.ERROR
                check.message = containment.message
                return check

            last_probe_state = AccessState.ALLOWED
            last_control_state: AccessState | None = None
            while time.monotonic() <= deadline:
                check.attempts += 1
                try:
                    remaining = deadline - time.monotonic()
                    probe = await asyncio.wait_for(
                        provider.verify_access(scenario.identity, target),
                        timeout=min(scenario.provider_timeout_seconds, remaining),
                    )
                except Exception as exc:  # A failed post-containment probe proves nothing.
                    check.indeterminate_attempts += 1
                    check.denial_confirmations = 0
                    check.first_denial_seconds = None
                    last_probe_state = AccessState.INDETERMINATE
                    append_event(
                        run.events,
                        "access.probe",
                        target.name,
                        {
                            "attempt": check.attempts,
                            "state": AccessState.INDETERMINATE,
                            "error": f"{type(exc).__name__}: {exc}",
                        },
                    )
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        await asyncio.sleep(min(scenario.poll_interval_seconds, remaining))
                    continue
                last_probe_state = probe.state
                subject_sample_seconds = round(time.monotonic() - containment_started, 3)
                append_event(
                    run.events,
                    "access.probe",
                    target.name,
                    {**probe.evidence, "attempt": check.attempts, "state": probe.state},
                )
                if probe.state == AccessState.INDETERMINATE:
                    check.indeterminate_attempts += 1
                    check.denial_confirmations = 0
                    check.first_denial_seconds = None
                elif probe.state == AccessState.ALLOWED:
                    check.denial_confirmations = 0
                    check.first_denial_seconds = None
                elif probe.state == AccessState.DENIED:
                    control = None
                    causal_sample = True
                    if control_enabled:
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            check.indeterminate_attempts += 1
                            causal_sample = False
                            last_control_state = AccessState.INDETERMINATE
                        else:
                            try:
                                control = await asyncio.wait_for(
                                    provider.verify_control_access(scenario.identity, target),
                                    timeout=min(scenario.provider_timeout_seconds, remaining),
                                )
                            except Exception as exc:  # A missing witness makes proof inconclusive.
                                check.indeterminate_attempts += 1
                                causal_sample = False
                                last_control_state = AccessState.INDETERMINATE
                                append_event(
                                    run.events,
                                    "access.control",
                                    target.name,
                                    {
                                        "attempt": check.attempts,
                                        "state": AccessState.INDETERMINATE,
                                        "error": f"{type(exc).__name__}: {exc}",
                                    },
                                )
                            else:
                                if control is None:
                                    check.indeterminate_attempts += 1
                                    causal_sample = False
                                    last_control_state = AccessState.INDETERMINATE
                                else:
                                    last_control_state = control.state
                                    check.control_accessible = (
                                        True
                                        if control.state == AccessState.ALLOWED
                                        else False
                                        if control.state == AccessState.DENIED
                                        else None
                                    )
                                    append_event(
                                        run.events,
                                        "access.control",
                                        target.name,
                                        {
                                            **control.evidence,
                                            "attempt": check.attempts,
                                            "state": control.state,
                                        },
                                    )
                                    causal_sample = control.state == AccessState.ALLOWED
                                    if not causal_sample:
                                        check.indeterminate_attempts += 1
                    if causal_sample:
                        if check.denial_confirmations == 0:
                            check.first_denial_seconds = subject_sample_seconds
                        check.denial_confirmations += 1
                    else:
                        check.denial_confirmations = 0
                        check.first_denial_seconds = None

                    if check.denial_confirmations >= target.denial_confirmation_attempts:
                        proof_seconds = time.monotonic() - containment_started
                        check.proof_seconds = round(proof_seconds, 3)
                        check.access_revoked = True
                        check.evidence = {
                            "baseline_control": (
                                control_baseline.evidence if control_baseline else None
                            ),
                            "subject": probe.evidence,
                            "control": control.evidence if control else None,
                            "first_denial_seconds": check.first_denial_seconds,
                            "proof_seconds": check.proof_seconds,
                        }
                        if proof_seconds <= check.containment_slo_seconds:
                            check.status = CheckStatus.PASS
                            if check.proof_mode == "subject-and-control":
                                witness = " while same-resource control access stayed healthy"
                            elif check.proof_mode == "subject-and-availability-witness":
                                witness = " while the availability witness stayed healthy"
                            else:
                                witness = ""
                            check.message = (
                                f"Explicit denial confirmed {check.denial_confirmations} times"
                                f"{witness}"
                            )
                        else:
                            check.status = CheckStatus.FAIL
                            check.message = "Access was denied, but the containment SLO was missed"
                        break
                else:
                    check.indeterminate_attempts += 1
                    check.denial_confirmations = 0
                    check.first_denial_seconds = None
                remaining = deadline - time.monotonic()
                if remaining > 0:
                    await asyncio.sleep(min(scenario.poll_interval_seconds, remaining))
            else:
                check.status = CheckStatus.FAIL
                if check.indeterminate_attempts:
                    control_note = (
                        f"; last control state was {last_control_state}"
                        if last_control_state is not None
                        else ""
                    )
                    check.message = (
                        "No controlled containment proof before the SLO: "
                        f"{check.indeterminate_attempts} probe sample(s) were indeterminate"
                        f"{control_note}"
                    )
                else:
                    check.message = "Access remained active or lacked enough denial confirmations before the SLO"
                check.evidence = {
                    "slo_seconds": check.containment_slo_seconds,
                    "last_subject_state": last_probe_state,
                    "last_control_state": last_control_state,
                }
        except Exception as exc:  # Providers are external boundaries.
            check.status = CheckStatus.ERROR
            check.message = f"{type(exc).__name__}: {exc}"
            append_event(run.events, "target.error", target.name, {"error": check.message})
        finally:
            check.elapsed_seconds = round(time.monotonic() - started, 3)
        return check
