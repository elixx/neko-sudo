"""Push subscription persistence: browsers come and go, the file persists."""

import pytest


SUB = {
    "endpoint": "https://fcm.googleapis.com/fcm/send/abc123",
    "keys": {"p256dh": "BPubKey...", "auth": "authSecret"},
}


def make_store(tmp_path):
    from gate.subscriptions import SubscriptionStore

    return SubscriptionStore(tmp_path / "subs.json")


def test_subscribe_persists_across_instances(tmp_path):
    store = make_store(tmp_path)
    store.add(SUB)
    again = make_store(tmp_path)
    assert again.all() == [SUB], "subscriptions must survive a restart"


def test_missing_file_starts_empty(tmp_path):
    assert make_store(tmp_path).all() == []


def test_remove_drops_subscription(tmp_path):
    store = make_store(tmp_path)
    store.add(SUB)
    store.remove(SUB["endpoint"])
    assert store.all() == []
    store.remove(SUB["endpoint"]), "removing an absent subscription is a no-op"


def test_resubscribe_replaces_same_endpoint(tmp_path):
    store = make_store(tmp_path)
    store.add(SUB)
    renewed = dict(SUB, keys={"p256dh": "BNew...", "auth": "auth2"})
    store.add(renewed)
    assert store.all() == [renewed], "one row per endpoint, refreshed keys win"


def test_malformed_subscription_is_rejected(tmp_path):
    store = make_store(tmp_path)
    with pytest.raises(ValueError):
        store.add({"endpoint": "not-a-url"})
    with pytest.raises(ValueError):
        store.add({"endpoint": SUB["endpoint"]})  # missing keys
    with pytest.raises(ValueError):
        store.add(
            {"endpoint": SUB["endpoint"], "keys": {"p256dh": "x"}}
        )  # missing auth
    assert store.all() == []
