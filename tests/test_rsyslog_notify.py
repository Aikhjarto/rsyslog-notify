import importlib.machinery
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "rsyslog-notify")
RSYSLOGD = shutil.which("rsyslogd") or ("/usr/sbin/rsyslogd" if os.path.exists("/usr/sbin/rsyslogd") else None)

loader = importlib.machinery.SourceFileLoader("rsyslog_notify", SCRIPT)
spec = importlib.util.spec_from_loader("rsyslog_notify", loader)
rf = importlib.util.module_from_spec(spec)
loader.exec_module(rf)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def wait_for(condition, timeout=10):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if condition():
            return True
        time.sleep(0.05)
    return False


class FakeSendxmpp:
    """A go-sendxmpp that appends its arguments and stdin to a JSON lines file."""

    def __init__(self, directory, fail_flag=None):
        self.path = os.path.join(directory, "go-sendxmpp")
        self.log = os.path.join(directory, "sent.jsonl")
        self.fail_flag = fail_flag or os.path.join(directory, "fail")
        with open(self.path, "w", encoding="utf-8") as handle:
            handle.write(textwrap.dedent("""\
                #!%s
                import json, os, sys
                if os.path.exists(%r):
                    sys.stderr.write("connection refused\\n")
                    sys.exit(1)
                with open(%r, "a") as log:
                    log.write(json.dumps({"args": sys.argv[1:], "text": sys.stdin.read()}) + "\\n")
                """ % (sys.executable, self.fail_flag, self.log)))
        os.chmod(self.path, 0o755)

    def sent(self):
        if not os.path.exists(self.log):
            return []
        return [json.loads(line) for line in read(self.log).splitlines()]


class FakeSMTP(threading.Thread):
    """Just enough SMTP for smtplib.send_message."""

    def __init__(self):
        super().__init__(daemon=True)
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(5)
        self.port = self.server.getsockname()[1]
        self.messages = []

    def run(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            with conn, conn.makefile("rwb") as stream:
                stream.write(b"220 fake\r\n")
                stream.flush()
                data = None
                for line in stream:
                    if data is not None:
                        if line == b".\r\n":
                            self.messages.append(b"".join(data).decode("utf-8"))
                            data = None
                            stream.write(b"250 ok\r\n")
                        else:
                            data.append(line[1:] if line.startswith(b"..") else line)
                        stream.flush()
                        continue
                    command = line[:4].upper()
                    if command == b"DATA":
                        data = []
                        stream.write(b"354 go\r\n")
                    elif command == b"QUIT":
                        stream.write(b"221 bye\r\n")
                        stream.flush()
                        break
                    else:
                        stream.write(b"250 ok\r\n")
                    stream.flush()

    def close(self):
        self.server.close()


class ParseTests(unittest.TestCase):
    def test_priority(self):
        self.assertEqual(rf.parse_priority("warning"), frozenset(range(5)))
        self.assertEqual(rf.parse_priority("err..notice"), frozenset({3, 4, 5}))
        self.assertEqual(rf.parse_priority("3"), frozenset(range(4)))
        self.assertEqual(rf.parse_priority("error"), frozenset(range(4)))
        with self.assertRaises(ValueError):
            rf.parse_priority("loud")

    def test_json(self):
        line = json.dumps({"msg": " disk full", "hostname": "nas", "programname": "smartd", "procid": "812",
                           "syslogfacility-text": "daemon", "syslogseverity": "2",
                           "timereported": "2026-10-05T10:11:12.345678+02:00"})
        message = rf.parse_line(line, 0, "auto")
        self.assertEqual((message.host, message.program, message.pid, message.facility, message.severity,
                          message.message), ("nas", "smartd", "812", "daemon", 2, "disk full"))
        self.assertAlmostEqual(message.time, 1791187872.345678, places=3)

    def test_rfc5424(self):
        line = "<132>1 2026-10-05T09:52:26.866618+02:00 heizungesp esphome - modbus [x@1 a=\"\\]\"] Stop waiting"
        message = rf.parse_line(line, 0, "auto")
        self.assertEqual((message.host, message.program, message.facility, message.severity, message.message),
                         ("heizungesp", "esphome", "local0", 4, "Stop waiting"))

    def test_bsd(self):
        message = rf.parse_line("<27>Oct  5 10:00:00 web nginx[42]: upstream timed out", 99, "auto")
        self.assertEqual((message.host, message.program, message.pid, message.facility, message.severity,
                          message.message, message.time),
                         ("web", "nginx", "42", "daemon", 3, "upstream timed out", 99))

    def test_plain_line_has_no_severity(self):
        message = rf.parse_line("something happened", 5, "auto")
        self.assertIsNone(message.severity)
        self.assertEqual(message.message, "something happened")
        self.assertIsNone(rf.parse_line("   \n", 5, "auto"))

    def test_rules(self):
        message = rf.Message(0, "web1", "sshd", "", "auth", 6, "Accepted publickey for root")
        levels = rf.parse_priority("warning")
        self.assertFalse(rf.selected(message, levels, [], []))
        self.assertTrue(rf.selected(message, levels, [rf.parse_rule("message=for root")], []))
        self.assertFalse(rf.selected(message, levels, [rf.parse_rule("message=for root")],
                                     [rf.parse_rule({"host": "^web", "program": "sshd"})]))
        self.assertTrue(rf.selected(message, levels, [rf.parse_rule({"host": "^web", "program": "sshd"})],
                                    [rf.parse_rule("host=^db")]))
        with self.assertRaises(ValueError):
            rf.parse_rule("colour=red")
        with self.assertRaises(ValueError):
            rf.parse_rule("message=(")

    def test_compose(self):
        messages = [rf.Message(0, "a", "p", "1", "", 3, "one"), rf.Message(0, "", "", "", "", None, "two")]
        subject, body = rf.compose(messages, 2, dict(rf.DEFAULTS), "local")
        self.assertEqual(subject, "[rsyslog] a, local: 4 message(s)")
        lines = body.splitlines()
        self.assertIn("2 older message(s) were dropped", lines[0])
        self.assertTrue(lines[1].endswith(" a p[1] err: one"))
        self.assertTrue(lines[2].endswith(" local ? ?: two"))

    def test_buffer_limit(self):
        config = rf.merge_config(rf.DEFAULTS, {"max_buffer": 3, "xmpp": {"to": ["x@example.org"]}})
        buffer = rf.Buffer(config, "local")
        for n in range(5):
            buffer.add(rf.Message(0, "", "", "", "", 3, str(n)))
        self.assertEqual([m.message for m in buffer.pending["xmpp"]], ["2", "3", "4"])
        self.assertEqual(buffer.dropped["xmpp"], 2)


class DaemonTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="rsyslog-notify-")
        self.addCleanup(shutil.rmtree, self.dir)
        self.xmpp = FakeSendxmpp(self.dir)

    def config(self, **extra):
        data = {"priority": "warning", "max_lines": 100, "interval": 60,
                "xmpp": {"to": ["admin@example.org"], "go_sendxmpp": self.xmpp.path, "config": "/dev/null"}}
        data.update(extra)
        path = os.path.join(self.dir, "config.yaml")
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(data, handle)       # JSON is YAML
        return path

    def start(self, *args, **extra):
        process = subprocess.Popen([sys.executable, SCRIPT, "-C", self.config(**extra)] + list(args),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, process)
        return process

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.kill()
            process.wait()
        for stream in filter(None, (process.stdin, process.stdout, process.stderr)):
            try:
                stream.close()
            except BrokenPipeError:
                pass

    def write(self, process, *lines):
        process.stdin.write("".join(line + "\n" for line in lines).encode("utf-8"))
        process.stdin.flush()

    def test_flush_on_pipe_close(self):
        process = self.start(exclude=[{"program": "^cron$"}], include=["message=(?i)password"])
        self.write(process,
                   "<27>Oct  5 10:00:00 web nginx[42]: upstream timed out",
                   "<30>Oct  5 10:00:01 web sshd[7]: wrong password for bob",
                   "<30>Oct  5 10:00:02 web sshd[7]: session opened",
                   "<75>Oct  5 10:00:03 web cron[9]: job failed")
        process.stdin.close()
        self.assertEqual(process.wait(10), 0, process.stderr.read())
        sent = self.xmpp.sent()
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["args"], ["-f", "/dev/null", "admin@example.org"])
        text = sent[0]["text"]
        self.assertTrue(text.startswith("[rsyslog] web: 2 message(s)\n\n"), text)
        self.assertIn("web nginx[42] err: upstream timed out", text)
        self.assertIn("web sshd[7] info: wrong password for bob", text)
        self.assertNotIn("session opened", text)
        self.assertNotIn("job failed", text)

    def test_nothing_selected_sends_nothing(self):
        process = self.start()
        self.write(process, "<30>Oct  5 10:00:02 web sshd[7]: session opened")
        process.stdin.close()
        self.assertEqual(process.wait(10), 0)
        self.assertEqual(self.xmpp.sent(), [])

    def test_max_lines(self):
        process = self.start(max_lines=2)
        self.write(process, "<27>a x: one", "<27>a x: two", "<27>a x: three")
        self.assertTrue(wait_for(lambda: len(self.xmpp.sent()) == 1))
        self.assertIn("2 message(s)", self.xmpp.sent()[0]["text"])
        process.stdin.close()
        self.assertEqual(process.wait(10), 0)
        self.assertEqual(len(self.xmpp.sent()), 2)
        self.assertIn("three", self.xmpp.sent()[1]["text"])

    def test_interval(self):
        process = self.start(interval=0.5)
        self.write(process, "<27>a x: one")
        self.assertTrue(wait_for(lambda: len(self.xmpp.sent()) == 1, 5))
        self.assertIsNone(process.poll())

    def test_sigterm_flushes(self):
        process = self.start()
        self.write(process, "<27>a x: one")
        time.sleep(0.5)
        process.send_signal(signal.SIGTERM)
        self.assertEqual(process.wait(10), 0)
        self.assertEqual(len(self.xmpp.sent()), 1)

    def test_sigusr1_flushes(self):
        process = self.start()
        self.write(process, "<27>a x: one")
        time.sleep(0.5)
        process.send_signal(signal.SIGUSR1)
        self.assertTrue(wait_for(lambda: len(self.xmpp.sent()) == 1, 5))
        self.assertIsNone(process.poll())

    def test_confirm(self):
        process = self.start("--confirm")
        self.assertEqual(process.stdout.readline(), b"OK\n")
        self.write(process, "<27>a x: one")
        self.assertEqual(process.stdout.readline(), b"OK\n")

    def test_failure_keeps_messages(self):
        open(self.xmpp.fail_flag, "w").close()
        process = self.start(max_lines=1)
        self.write(process, "<27>a x: one")
        time.sleep(1)
        os.unlink(self.xmpp.fail_flag)
        self.write(process, "<27>a x: two")      # waits for the retry; sent at exit
        process.stdin.close()
        self.assertEqual(process.wait(10), 0)
        sent = self.xmpp.sent()
        self.assertEqual(len(sent), 1)
        self.assertIn("one", sent[0]["text"])
        self.assertIn("two", sent[0]["text"])
        self.assertIn("connection refused", process.stderr.read().decode())

    def test_failure_at_exit(self):
        open(self.xmpp.fail_flag, "w").close()
        process = self.start()
        self.write(process, "<27>a x: one")
        process.stdin.close()
        self.assertEqual(process.wait(10), 1)

    def test_mail(self):
        smtp = FakeSMTP()
        smtp.start()
        self.addCleanup(smtp.close)
        process = self.start(mail={"to": ["root@example.org"], "from": "log@example.org", "port": smtp.port})
        self.write(process, '{"msg": "disk full", "hostname": "nas", "programname": "smartd", "syslogseverity": 2}')
        process.stdin.close()
        self.assertEqual(process.wait(10), 0, process.stderr.read())
        self.assertEqual(len(smtp.messages), 1)
        self.assertIn("Subject: [rsyslog] nas: 1 message(s)", smtp.messages[0])
        self.assertIn("To: root@example.org", smtp.messages[0])
        self.assertIn("nas smartd crit: disk full", smtp.messages[0])
        self.assertEqual(len(self.xmpp.sent()), 1)

    def test_usage_errors(self):
        result = subprocess.run([sys.executable, SCRIPT, "-C", self.config(xmpp={})], stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"no recipients", result.stderr)
        result = subprocess.run([sys.executable, SCRIPT, "-C", self.config(include=["colour=red"])],
                                stderr=subprocess.PIPE)
        self.assertEqual(result.returncode, 2)


@unittest.skipUnless(RSYSLOGD, "rsyslogd is not installed")
class RsyslogTests(unittest.TestCase):
    """rsyslogd with omprog in front of rsyslog-notify, fed via imtcp."""

    def test_omprog(self):
        directory = tempfile.mkdtemp(prefix="rsf-", dir="/tmp")
        self.addCleanup(shutil.rmtree, directory)
        xmpp = FakeSendxmpp(directory)
        config = os.path.join(directory, "notify.yaml")
        with open(config, "w", encoding="utf-8") as handle:
            json.dump({"priority": "warning", "max_lines": 100, "interval": 60,
                       "xmpp": {"to": ["admin@example.org"], "go_sendxmpp": xmpp.path}}, handle)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        conf = os.path.join(directory, "rsyslog.conf")
        with open(conf, "w", encoding="utf-8") as handle:
            handle.write(textwrap.dedent("""\
                global(workDirectory="{d}")
                module(load="imtcp")
                module(load="omprog")
                input(type="imtcp" address="127.0.0.1" port="{port}" ruleset="r")
                ruleset(name="r") {{
                    action(type="omprog" binary="{py} {script} -C {config} --confirm" template="RSYSLOG_ForwardFormat"
                           confirmMessages="on" signalOnClose="on")
                }}
                """).format(d=directory, port=port, py=sys.executable, script=SCRIPT, config=config))
        process = subprocess.Popen([RSYSLOGD, "-n", "-f", conf, "-i", os.path.join(directory, "pid")],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.addCleanup(DaemonTests.stop, process)

        def connect():
            try:
                self.sender = socket.create_connection(("127.0.0.1", port), timeout=1)
                return True
            except OSError:
                return False
        self.assertTrue(wait_for(connect), "rsyslogd does not listen")
        with self.sender:
            self.sender.sendall(b"<27>Oct  5 10:00:00 web nginx[42]: upstream timed out\n"
                                b"<30>Oct  5 10:00:01 web sshd[7]: session opened\n")
        time.sleep(1)
        process.send_signal(signal.SIGTERM)
        process.wait(15)
        sent = xmpp.sent()
        self.assertEqual(len(sent), 1, process.stderr.read())
        self.assertIn("web nginx[42] err: upstream timed out", sent[0]["text"])
        self.assertNotIn("session opened", sent[0]["text"])


if __name__ == "__main__":
    unittest.main()
