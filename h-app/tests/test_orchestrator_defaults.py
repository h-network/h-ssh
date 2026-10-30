from hssh.model import Credentials, EditSettings, PolicySettings, RecordSettings, RunSpec, SafetySettings, Target, Timeouts
from hssh.orchestrator import defaults
from hssh.orchestrator.defaults import complete, default_credentials

T = Target("r1", "10.0.0.1", "junos", "netconf")


def test_complete_fills_every_default_and_leaves_safety_and_recording_off():
    spec = complete(RunSpec((T,), "show", commands=("show version",)))
    assert spec.credentials == default_credentials()
    assert spec.timeouts == defaults.DEFAULT_TIMEOUTS
    assert spec.workers == defaults.DEFAULT_WORKERS
    assert spec.host_key_policy == defaults.DEFAULT_HOST_KEY_POLICY
    assert spec.probe is defaults.DEFAULT_PROBE
    assert spec.skip_unreachable is defaults.DEFAULT_SKIP_UNREACHABLE
    assert spec.edit == defaults.DEFAULT_EDIT
    assert spec.policy == defaults.DEFAULT_POLICY
    assert spec.safety is None and spec.recording is None


def test_complete_keeps_what_the_caller_set_including_false_and_zero():
    given = RunSpec((T,), "edit", config_lines=("set a",), credentials=Credentials("op", "pw"),
                    timeouts=Timeouts(1, 2, 3, 4), workers=1, host_key_policy="strict", probe=False,
                    skip_unreachable=True, edit=EditSettings(apply=True, confirmed_minutes=3),
                    policy=PolicySettings(retries=0, retry_pause=0), safety=SafetySettings(10, 2),
                    recording=RecordSettings(store_path="x.db"))
    assert complete(given) == given


def test_the_defaults_are_the_documented_values():
    assert defaults.DEFAULT_TIMEOUTS == Timeouts(connect=3, setup=30, command=20, commit=60)
    assert defaults.DEFAULT_POLICY == PolicySettings(retries=2, retry_pause=2)
    assert defaults.CONNECT_BACKOFF == (0.5, 1.0)
    assert defaults.DEFAULT_SAFETY == SafetySettings(cooldown_seconds=300, rate_limit=6)
    assert defaults.DEFAULT_EDIT == EditSettings(apply=False)
    assert (defaults.DEFAULT_WORKERS, defaults.DEFAULT_HOST_KEY_POLICY, defaults.DEFAULT_PROBE) == (8, "off", True)


def test_default_credentials_name_the_login_user_with_no_secret():
    creds = default_credentials()
    assert creds.username == defaults.default_username()
    assert creds.password is None and creds.key_file is None
