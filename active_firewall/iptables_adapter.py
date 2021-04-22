import subprocess


class IptablesAdapter:

    def __init__(self, chain):
        self.chain = chain

    def add_rule(self, rule):
        add = ["sudo", "iptables", "-A", self.chain, "-j", "DROP"]
        new_rules = add + rule
        subprocess.call(new_rules)

    def delete_rule(self, rule):
        delete = ["sudo", "iptables", self.chain, "-j", "DROP"]
        new_rules = delete + rule
        subprocess.call(new_rules)
