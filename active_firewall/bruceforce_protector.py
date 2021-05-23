class BruteForceProtector:

    def __init__(self, iptables_adapter):
        self.iptables_adapter = iptables_adapter

    numOfAuthTries = 5
    time = 100 

    def __set_BruteForce_rules:
        self.iptables_adapter.add_rule(["INPUT", "-p", "tcp", "-m", "tcp", "--dport", "22", "-m", "state", "--state", "NEW", "-m", "recent", "--set", "--name", "SSH", "--rsource"])
        self.iptables_adapter.add_rule(["INPUT", "-p", "tcp", "-m", "tcp", "--dport", "22", "-m", "recent", "--rcheck", "--seconds", str(time), "--hitcount", str(numOfAuthTries), "--rttl", "--name", "SSH", "--rsource", "-j", "REJECT", "--reject-with", "tcp-reset"])
        self.iptables_adapter.add_rule(["INPUT", "-p", "tcp", "-m", "tcp", "--dport", "22", "-m", "recent", "--rcheck", "--seconds", str(time), "--hitcount", str(numOfAuthTries), "--rttl", "--name", "SSH", "--rsource", "-j", "LOG", "--log-prefix", "SSHBruteForce"])
        self.iptables_adapter.add_rule(["INPUT", "-p", "tcp", "-m", "tcp", "--dport", "22", "-m", "recent", "--update", "--seconds", str(time), "--hitcount", str(numOfAuthTries), "--rttl", "--name", "SSH", "--rsource", "-j", "REJECT", "--reject-with", "tcp-reset"])
        self.iptables_adapter.add_rule(["INPUT", "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"])
