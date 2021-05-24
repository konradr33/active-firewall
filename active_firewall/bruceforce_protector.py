class BruteForceProtector:
    """
    Class that can apply on iptables a set of rules protecting the port used to log into the device
    """

    def __init__(self, iptables_adapter, num_of_auth_tries, timeout, auth_port):
        """
        Constructor method

        :param iptables_adapter: instance of IptablesAdapter for applying firewall rules
        :type iptables_adapter: IptablesAdapter
        :param num_of_auth_tries: number of connections before restrictions applied
        :type iptables_adapter: int
        :param timeout: time of restricting connection after exceeding num_of_auth_tries
        :type timeout: int
        :param auth_port: number of port to protect
        :type auth_port: int
        """
        self.iptables_adapter = iptables_adapter
        self.num_of_auth_tries = num_of_auth_tries
        self.timeout = timeout
        self.auth_port = auth_port

    def apply_rules(self):
        """
        The function applies rules to instance of iptables adapter
        """
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
