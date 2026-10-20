"""Affinity length cap, pool pages, and pool-sized chat concurrency.

Two independent limits that both used to be fixed constants:

* ``derive_affinity_key`` pinned every conversation to one upstream account so
  the account-level prompt cache keeps hitting. That is right for normal
  conversations, but a conversation's body grows monotonically, and past a few
  hundred messages the oversized request makes the upstream drop the
  connection. ``WB_AFFINITY_MAX_MSGS`` releases the pin once a conversation is
  that long, trading its prefix cache for not being retried.

  What it is released *into* is ``WB_AFFINITY_PAGE_SIZE``: 0 sends the
  conversation back to the whole pool (the 1.6.x behaviour), 1 keeps it pinned
  (the cap switched off), and anything higher rotates it over one page of the
  pool so every account of that page keeps a warm copy of the prefix. The page
  tests below pin the boundary; the pool side is in ``_test_affinity_pages.py``.

* ``MAX_CONCURRENT_CHAT`` was a fixed 32 regardless of pool size.
  ``WB_MAX_CONCURRENT_CHAT=auto`` sizes it from the ready-account count.

Run with: python _test_affinity_length_cap.py
No upstream credentials or outbound network are used.
"""
import os
import sys
import tempfile
import threading
import unittest

_startup_dir = tempfile.TemporaryDirectory(prefix="affinity-cap-")
os.environ["ACCOUNTS_DIR"] = _startup_dir.name
os.environ["WB_PROXY_USAGE_DIR"] = _startup_dir.name
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ca_proxy


def conversation(length):
    """A conversation of exactly `length` messages, stable prefix first."""
    msgs = [{"role": "system", "content": "you are a helpful assistant"}]
    for i in range(max(0, length - 1)):
        msgs.append({"role": "user" if i % 2 == 0 else "assistant",
                     "content": "turn %d" % i})
    return msgs


class AffinityLengthCapTests(unittest.TestCase):
    """The cap must only touch conversations past the threshold."""

    def setUp(self):
        self._saved = ca_proxy.AFFINITY_MAX_MSGS
        self._saved_page = ca_proxy.AFFINITY_PAGE_SIZE
        # The 1.6.x behaviour the release tests pin: no page, back to the pool.
        ca_proxy.AFFINITY_PAGE_SIZE = 0

    def tearDown(self):
        ca_proxy.AFFINITY_MAX_MSGS = self._saved
        ca_proxy.AFFINITY_PAGE_SIZE = self._saved_page

    def test_short_conversations_still_bind(self):
        ca_proxy.AFFINITY_MAX_MSGS = 400
        for length in (1, 2, 10, 399, 400):
            key = ca_proxy.derive_affinity_key(conversation(length))
            self.assertTrue(key, "msgs=%d should keep its affinity key" % length)
            self.assertTrue(key.startswith("pfx-"))

    def test_long_conversations_are_released_when_the_page_is_off(self):
        ca_proxy.AFFINITY_MAX_MSGS = 400
        for length in (401, 500, 1245):
            self.assertIsNone(
                ca_proxy.derive_affinity_key(conversation(length)),
                "msgs=%d should be released so the pool can rotate" % length)

    def test_threshold_is_inclusive(self):
        """msgs == cap binds; the cap is a limit, not an off-by-one."""
        ca_proxy.AFFINITY_MAX_MSGS = 3
        self.assertIsNotNone(ca_proxy.derive_affinity_key(conversation(3)))
        self.assertIsNone(ca_proxy.derive_affinity_key(conversation(4)))

    def test_zero_disables_the_cap(self):
        """0 keeps the pre-1.6.x behaviour: always bind."""
        ca_proxy.AFFINITY_MAX_MSGS = 0
        for length in (1, 400, 5000):
            self.assertIsNotNone(ca_proxy.derive_affinity_key(conversation(length)))

    def test_bound_conversations_keep_a_stable_key(self):
        """The whole point: later turns of one conversation share one account."""
        ca_proxy.AFFINITY_MAX_MSGS = 400
        first = ca_proxy.derive_affinity_key(conversation(10))
        later = ca_proxy.derive_affinity_key(conversation(300))
        self.assertEqual(first, later)

    def test_distinct_conversations_do_not_collide(self):
        ca_proxy.AFFINITY_MAX_MSGS = 400
        a = conversation(10)
        b = conversation(10)
        b[1] = {"role": "user", "content": "a different opening turn"}
        self.assertNotEqual(ca_proxy.derive_affinity_key(a),
                            ca_proxy.derive_affinity_key(b))

    def test_degenerate_inputs_are_safe(self):
        ca_proxy.AFFINITY_MAX_MSGS = 400
        self.assertIsNone(ca_proxy.derive_affinity_key(None))
        self.assertIsNone(ca_proxy.derive_affinity_key([]))


class AffinityPageTests(unittest.TestCase):
    """Past the cap a conversation rotates over one page, not the whole pool."""

    def setUp(self):
        self._saved_msgs = ca_proxy.AFFINITY_MAX_MSGS
        self._saved_page = ca_proxy.AFFINITY_PAGE_SIZE
        self._saved_prefix = ca_proxy.AFFINITY_BY_PREFIX
        ca_proxy.AFFINITY_MAX_MSGS = 400

    def tearDown(self):
        ca_proxy.AFFINITY_MAX_MSGS = self._saved_msgs
        ca_proxy.AFFINITY_PAGE_SIZE = self._saved_page
        ca_proxy.AFFINITY_BY_PREFIX = self._saved_prefix

    def test_a_long_conversation_gets_a_key_and_a_page(self):
        ca_proxy.AFFINITY_PAGE_SIZE = 3
        key, page = ca_proxy.affinity_route(conversation(500))
        self.assertTrue(key and key.startswith("pfx-"))
        self.assertIsNotNone(page, "500 msgs must rotate over a page")
        index, size = page
        self.assertEqual(size, 3)
        self.assertTrue(0 <= index < size, "page index out of range: %r" % (page,))

    def test_the_key_survives_crossing_the_cap(self):
        """One conversation, one key: the binding carries over the boundary."""
        ca_proxy.AFFINITY_PAGE_SIZE = 3
        short = ca_proxy.derive_affinity_key(conversation(400))
        long_key = ca_proxy.derive_affinity_key(conversation(500))
        self.assertEqual(short, long_key)

    def test_the_page_is_stable_across_turns(self):
        ca_proxy.AFFINITY_PAGE_SIZE = 3
        first = ca_proxy.affinity_route(conversation(401))[1]
        later = ca_proxy.affinity_route(conversation(900))[1]
        self.assertEqual(first, later)

    def test_distinct_conversations_spread_over_pages(self):
        ca_proxy.AFFINITY_PAGE_SIZE = 3
        pages = set()
        for index in range(60):
            msgs = conversation(500)
            msgs[1] = {"role": "user", "content": "conversation %d" % index}
            pages.add(ca_proxy.affinity_route(msgs)[1][0])
        self.assertGreater(len(pages), 1,
                           "every conversation landing on one page would be a "
                           "pin with extra steps")

    def test_page_size_one_pins_instead(self):
        ca_proxy.AFFINITY_PAGE_SIZE = 1
        key, page = ca_proxy.affinity_route(conversation(500))
        self.assertTrue(key, "1 means pinned, so the conversation keeps its key")
        self.assertIsNone(page)

    def test_page_size_zero_keeps_the_pool_rotation(self):
        ca_proxy.AFFINITY_PAGE_SIZE = 0
        key, page = ca_proxy.affinity_route(conversation(500))
        self.assertIsNone(key)
        self.assertIsNone(page)

    def test_the_route_and_the_key_agree(self):
        ca_proxy.AFFINITY_PAGE_SIZE = 3
        for length in (10, 400, 500):
            msgs = conversation(length)
            self.assertEqual(ca_proxy.derive_affinity_key(msgs),
                             ca_proxy.affinity_route(msgs)[0])

    def test_switching_prefix_affinity_off_releases_everything(self):
        ca_proxy.AFFINITY_PAGE_SIZE = 3
        ca_proxy.AFFINITY_BY_PREFIX = False
        for length in (10, 500):
            self.assertEqual(ca_proxy.affinity_route(conversation(length)),
                             (None, None))

    def test_degenerate_inputs_are_safe(self):
        ca_proxy.AFFINITY_PAGE_SIZE = 3
        for msgs in (None, []):
            self.assertEqual(ca_proxy.affinity_route(msgs), (None, None))


class ChatSlotResizeTests(unittest.TestCase):
    """resize_chat_slots grows the ceiling, never shrinks it."""

    def setUp(self):
        self._auto = ca_proxy.CHAT_SLOTS_AUTO
        self._max = ca_proxy.MAX_CONCURRENT_CHAT
        self._slots = ca_proxy._chat_slots

    def tearDown(self):
        ca_proxy.CHAT_SLOTS_AUTO = self._auto
        ca_proxy.MAX_CONCURRENT_CHAT = self._max
        ca_proxy._chat_slots = self._slots

    def test_auto_sizes_from_the_pool(self):
        ca_proxy.CHAT_SLOTS_AUTO = True
        ca_proxy.MAX_CONCURRENT_CHAT = ca_proxy.CHAT_SLOTS_FLOOR
        self.assertEqual(ca_proxy.resize_chat_slots(110), 110)
        self.assertEqual(ca_proxy.MAX_CONCURRENT_CHAT, 110)
        # The new semaphore really does carry that many permits.
        acquired = 0
        while ca_proxy._chat_slots.acquire(blocking=False):
            acquired += 1
        self.assertEqual(acquired, 110)
        for _ in range(acquired):
            ca_proxy._chat_slots.release()

    def test_small_pool_falls_back_to_the_floor(self):
        ca_proxy.CHAT_SLOTS_AUTO = True
        ca_proxy.MAX_CONCURRENT_CHAT = ca_proxy.CHAT_SLOTS_FLOOR
        self.assertEqual(ca_proxy.resize_chat_slots(3), ca_proxy.CHAT_SLOTS_FLOOR)

    def test_never_shrinks(self):
        """A shrink would let releases exceed the ceiling and raise ValueError."""
        ca_proxy.CHAT_SLOTS_AUTO = True
        ca_proxy.MAX_CONCURRENT_CHAT = ca_proxy.CHAT_SLOTS_FLOOR
        ca_proxy.resize_chat_slots(200)
        slots = ca_proxy._chat_slots
        self.assertEqual(ca_proxy.resize_chat_slots(5), 200)
        self.assertIs(ca_proxy._chat_slots, slots)

    def test_fixed_setting_is_a_no_op(self):
        """A numeric WB_MAX_CONCURRENT_CHAT keeps the 1.6.x behaviour."""
        ca_proxy.CHAT_SLOTS_AUTO = False
        ca_proxy.MAX_CONCURRENT_CHAT = 32
        slots = ca_proxy._chat_slots
        self.assertEqual(ca_proxy.resize_chat_slots(500), 32)
        self.assertEqual(ca_proxy.MAX_CONCURRENT_CHAT, 32)
        self.assertIs(ca_proxy._chat_slots, slots)

    def test_garbage_input_is_ignored(self):
        ca_proxy.CHAT_SLOTS_AUTO = True
        ca_proxy.MAX_CONCURRENT_CHAT = ca_proxy.CHAT_SLOTS_FLOOR
        self.assertEqual(ca_proxy.resize_chat_slots(None), ca_proxy.CHAT_SLOTS_FLOOR)
        self.assertEqual(ca_proxy.resize_chat_slots("abc"), ca_proxy.CHAT_SLOTS_FLOOR)


class SlotAccountingTests(unittest.TestCase):
    """A resize must not corrupt the in-flight count."""

    def test_resize_preserves_held_slots(self):
        saved_auto = ca_proxy.CHAT_SLOTS_AUTO
        saved_max = ca_proxy.MAX_CONCURRENT_CHAT
        saved_slots = ca_proxy._chat_slots
        try:
            ca_proxy.CHAT_SLOTS_AUTO = True
            ca_proxy.MAX_CONCURRENT_CHAT = ca_proxy.CHAT_SLOTS_FLOOR
            ca_proxy._chat_slots = threading.BoundedSemaphore(ca_proxy.CHAT_SLOTS_FLOOR)
            self.assertTrue(ca_proxy._chat_slots.acquire(blocking=False))
            ca_proxy.resize_chat_slots(64)
            # The permit taken before the resize belongs to the old semaphore;
            # releasing it there must not raise on the new one.
            for _ in range(64):
                self.assertTrue(ca_proxy._chat_slots.acquire(blocking=False))
            for _ in range(64):
                ca_proxy._chat_slots.release()
        finally:
            ca_proxy.CHAT_SLOTS_AUTO = saved_auto
            ca_proxy.MAX_CONCURRENT_CHAT = saved_max
            ca_proxy._chat_slots = saved_slots


if __name__ == "__main__":
    unittest.main(verbosity=2)
