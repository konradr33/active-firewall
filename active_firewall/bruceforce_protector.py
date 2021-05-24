class BruteForceProtector:

    def __init__(self, iptables_adapter, num_of_auth_tries, timeout, auth_port):
        self.iptables_adapter = iptables_adapter
        self.num_of_auth_tries = num_of_auth_tries
        self.timeout = timeout
        self.auth_port = auth_port

    def apply_rules(self):
        self.iptables_adapter.add_custom_rule(
            ["-p", "tcp", "-m", "tcp", "--dport", str(self.auth_port), "-m", "state", "--state", "NEW", "-m", "recent",
             "--set", "--name", "SSH", "--rsource"])
        self.iptables_adapter.add_custom_rule(
            ["-p", "tcp", "-m", "tcp", "--dport", str(self.auth_port), "-m", "recent", "--rcheck", "--seconds",
             str(self.timeout),
             "--hitcount", str(self.num_of_auth_tries), "--rttl", "--name", "SSH", "--rsource", "-j", "REJECT",
             "--reject-with",
             "tcp-reset"])
        self.iptables_adapter.add_custom_rule(
            ["-p", "tcp", "-m", "tcp", "--dport", str(self.auth_port), "-m", "recent", "--rcheck", "--seconds",
             str(self.timeout),
             "--hitcount", str(self.num_of_auth_tries), "--rttl", "--name", "SSH", "--rsource", "-j", "LOG",
             "--log-prefix",
             "SSHBruteForce"])
        self.iptables_adapter.add_custom_rule(
            ["-p", "tcp", "-m", "tcp", "--dport", str(self.auth_port), "-m", "recent", "--update", "--seconds",
             str(self.timeout),
             "--hitcount", str(self.num_of_auth_tries), "--rttl", "--name", "SSH", "--rsource", "-j", "REJECT",
             "--reject-with",
             "tcp-reset"])
        self.iptables_adapter.add_custom_rule(
            ["-p", "tcp", "-m", "tcp", "--dport", str(self.auth_port), "-j", "ACCEPT"])
